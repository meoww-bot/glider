package rule

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/meoww-bot/glider/pkg/log"
	"github.com/meoww-bot/glider/proxy"
)

// Proxy implements the proxy.Proxy interface with rule support.
type Proxy struct {
	main      *FwdrGroup
	all       []*FwdrGroup
	domainMap sync.Map
	ipMap     sync.Map
	cidrMap   sync.Map
	provider  *ProviderGroup
}

// NewProxy returns a new rule proxy.
func NewProxy(mainForwarders []string, mainStrategy *Strategy, rules []*Config, ForwardsProvider []string, ForwardsExclude []string, ForwardsInclude []string) *Proxy {
	rd := &Proxy{
		main:     NewFwdrGroup("main", mainForwarders, mainStrategy),
		provider: NewProviderGroup(ForwardsProvider, ForwardsExclude, ForwardsInclude),
	}

	for _, r := range rules {
		group := NewFwdrGroup(r.RulePath, r.Forward, &r.Strategy)
		rd.all = append(rd.all, group)

		for _, domain := range r.Domain {
			rd.domainMap.Store(strings.ToLower(domain), group)
		}

		for _, s := range r.IP {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				log.F("[rule] parse ip error: %s", err)
				continue
			}
			rd.ipMap.Store(ip, group)
		}

		for _, s := range r.CIDR {
			cidr, err := netip.ParsePrefix(s)
			if err != nil {
				log.F("[rule] parse cidr error: %s", err)
				continue
			}
			rd.cidrMap.Store(cidr, group)
		}
	}

	direct := NewFwdrGroup("", nil, mainStrategy)
	rd.domainMap.Store("direct", direct)

	// if there's any forwarder defined in main config, make sure they will be accessed directly.
	if len(mainForwarders) > 0 {
		for _, f := range rd.main.fwdrs {
			addr := strings.Split(f.addr, ",")[0]
			host, _, _ := net.SplitHostPort(addr)
			if _, err := netip.ParseAddr(host); err != nil {
				rd.domainMap.Store(strings.ToLower(host), direct)
			}
		}
	}

	return rd
}

// Dial dials to targer addr and return a conn.
func (p *Proxy) Dial(network, addr string) (net.Conn, proxy.Dialer, error) {
	return p.findDialer(addr).Dial(network, addr)
}

// DialUDP connects to the given address via the proxy.
func (p *Proxy) DialUDP(network, addr string) (pc net.PacketConn, dialer proxy.UDPDialer, err error) {
	return p.findDialer(addr).DialUDP(network, addr)
}

// findDialer returns a dialer by dstAddr according to rule.
func (p *Proxy) findDialer(dstAddr string) *FwdrGroup {
	host, _, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return p.main
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		// check ip
		if proxy, ok := p.ipMap.Load(ip); ok {
			return proxy.(*FwdrGroup)
		}

		// check cidr
		var ret *FwdrGroup
		p.cidrMap.Range(func(key, value any) bool {
			if key.(netip.Prefix).Contains(ip) {
				ret = value.(*FwdrGroup)
				return false
			}
			return true
		})

		if ret != nil {
			return ret
		}
	}

	// check host
	host = strings.ToLower(host)
	for i := len(host); i != -1; {
		i = strings.LastIndexByte(host[:i], '.')
		if proxy, ok := p.domainMap.Load(host[i+1:]); ok {
			return proxy.(*FwdrGroup)
		}
	}

	return p.main
}

// NextDialer returns next dialer according to rule.
func (p *Proxy) NextDialer(dstAddr string) proxy.Dialer {
	return p.findDialer(dstAddr).NextDialer(dstAddr)
}

// Record records result while using the dialer from proxy.
func (p *Proxy) Record(dialer proxy.Dialer, success bool) {
	if fwdr, ok := dialer.(*Forwarder); ok {
		if !success {
			fwdr.IncFailures()
			return
		}
		fwdr.Enable()
	}
}

// AddDomainIP used to update ipMap rules according to domainMap rule.
func (p *Proxy) AddDomainIP(domain string, ip netip.Addr) error {
	domain = strings.ToLower(domain)
	for i := len(domain); i != -1; {
		i = strings.LastIndexByte(domain[:i], '.')
		if dialer, ok := p.domainMap.Load(domain[i+1:]); ok {
			p.ipMap.Store(ip, dialer)
			// log.F("[rule] update map: %s/%s based on rule: domain=%s\n", domain, ip, domain[i+1:])
		}
	}
	return nil
}

// Check checks availability of forwarders inside proxy.
func (p *Proxy) Check() {
	p.main.Check()

	for _, fwdrGroup := range p.all {
		fwdrGroup.Check()
	}
}

func GetPageContent(url string) (content string, err error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// 设置 Referer 标头
	req.Header.Set("Referer", "https://www.baidu.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	pageBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(pageBytes), nil
}

func (p *Proxy) Fetch() {

	var currentFwdrs []string

	for _, fwdr := range p.main.fwdrs {
		currentFwdrs = append(currentFwdrs, fwdr.url)
	}

	var content string
	for _, urlstring := range p.provider.url {

		parsedURL, err := url.Parse(urlstring)
		if err != nil {
			log.F("[provider] parse provider url: %s, error: %s", urlstring, err)
			return
		}

		// 获取主机信息
		host := parsedURL.Host
		content, err = GetPageContent(urlstring)
		if err != nil {
			log.F("[provider] get %s err %s ", host, err)

		}
		paddingContent := addPaddingIfNeeded(content)
		rawContent, _ := base64.StdEncoding.DecodeString(paddingContent)

		lines := strings.Split(string(rawContent), "\n")
		for _, line := range lines {

			if len(line) == 0 {
				break
			}

			// 某些机场使用空 SNI 的节点配置，用于显示流量信息，跳过处理
			if strings.Contains(line, "peer=&sni=#Info") {
				continue
			}

			// check include
			// 因为不确定用户是否使用这个配置，所以没有一开始先处理订阅中每行的代理
			if len(p.provider.includes) > 0 {
				for _, include := range p.provider.includes {

					var paddingStr1, decodedStr1 string

					// vmess json regard as string
					if strings.HasPrefix(line, "vmess://") {
						paddingStr1 = addPaddingIfNeeded(strings.Replace(line, "vmess://", "", 1))

						decodedBytes, _ := base64.StdEncoding.DecodeString(paddingStr1)

						decodedStr1 = string(decodedBytes)

					} else if strings.HasPrefix(line, "trojan://") || strings.HasPrefix(line, "ss://") {
						// trojan urlencode
						// ss urlencode

						decodedStr1, _ = url.QueryUnescape(strings.Split(line, "#")[1])
					}

					if strings.Contains(decodedStr1, include) {
						log.F("[provider] add [%s], include keyword [%s]", decodedStr1, include)

						if !slices.Contains(currentFwdrs, line) {
							fwdr, err := ForwarderFromURL(line, "",
								time.Duration(3)*time.Second, time.Duration(0)*time.Second)
							if err != nil {
								log.Fatal(err)
							}
							fwdr.SetMaxFailures(uint32(3))
							p.main.fwdrs = append(p.main.fwdrs, fwdr)

							fwdr.AddHandler(p.main.OnStatusChanged)
						}

						// when matched, skip next check include
						break

					}

				}
				// omit forwardsinclude
				continue
			}

			// check exclude
			// 因为不确定用户是否使用这个配置，所以没有一开始先处理订阅中每行的代理
			if len(p.provider.excludes) > 0 {
				for _, exclude := range p.provider.excludes {

					var paddingStr2, decodedStr2 string

					// trojan

					// vmess
					// json regard as string
					if strings.HasPrefix(line, "vmess://") {
						paddingStr2 = addPaddingIfNeeded(strings.Replace(line, "vmess://", "", 1))

						decodedBytes, _ := base64.StdEncoding.DecodeString(paddingStr2)

						decodedStr2 = string(decodedBytes)

					}

					if strings.Contains(decodedStr2, exclude) {
						log.F("[provider] skip add %s, exclude keyword %s", line, exclude)
						continue
					}
				}
			}

			if !slices.Contains(currentFwdrs, line) {
				fwdr, err := ForwarderFromURL(line, "",
					time.Duration(3)*time.Second, time.Duration(0)*time.Second)
				if err != nil {
					log.F("[provider] skip error : %s", err)
					continue
				}
				fwdr.SetMaxFailures(uint32(3))
				p.main.fwdrs = append(p.main.fwdrs, fwdr)

				fwdr.AddHandler(p.main.OnStatusChanged)
			}

		}

	}
	// for _, f := range p.main.fwdrs {
	// 	f.AddHandler(p.main.OnStatusChanged)
	// }
}

func addPaddingIfNeeded(base64String string) string {
	// 计算需要添加的填充字符数量
	padding := strings.Repeat("=", (4-len(base64String)%4)%4)
	return base64String + padding
}
