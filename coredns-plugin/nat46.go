package nat46

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin(PluginName)

// UpstreamInt wraps the Upstream API for dependency injection during testing
type UpstreamInt interface {
	Lookup(ctx context.Context, state request.Request, name string, typ uint16) (*dns.Msg, error)
}

type Nat46 struct {
	Next        plugin.Handler
	domains     [][]string
	ipv6Prefix  net.IPNet
	nat46Device string
	upstream    UpstreamInt
}

func NewNat46(domainsFileName string, ipv6Prefix string, nat46Device string, upstream UpstreamInt) (Nat46, error) {
	domainsFile, err := os.Open(domainsFileName)
	if err != nil {
		return Nat46{}, plugin.Error(PluginName, err)
	}

	log.Debugf("Reading domains from %s", domainsFileName)
	domains := [][]string{}
	defer domainsFile.Close()
	scanner := bufio.NewScanner(domainsFile)
	for scanner.Scan() {
		domain := strings.Split(scanner.Text(), ".")
		slices.Reverse(domain)
		log.Debugf("nat46 domain: %v", domain)
		domains = append(domains, domain)
	}

	_, prefix, err := net.ParseCIDR(ipv6Prefix)
	if err != nil {
		return Nat46{}, plugin.Error(PluginName, err)
	}
	log.Debugf("IPV6 prefix: %v", prefix)
	log.Debugf("NAT46 deivice: '%s'", nat46Device)

	return Nat46{domains: domains, ipv6Prefix: *prefix, nat46Device: nat46Device, upstream: upstream}, nil
}

// ServeDNS implements the plugin.Handler interface. This method gets called when nat46 is used
// in a Server.
func (nat46 Nat46) ServeDNS(ctx context.Context, responseWriter dns.ResponseWriter, dnsMsg *dns.Msg) (int, error) {
	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	log.Debugf(fmt.Sprintf("Received request: %v", dnsMsg.Question))

	// Don't proxy if we don't need to.
	req := request.Request{W: responseWriter, Req: dnsMsg}
	if !nat46.requestShouldIntercept(&req) {
		return nat46.Next.ServeDNS(ctx, responseWriter, dnsMsg)
	}

	// Wrap.
	pw := NewResponseInterceptor(nat46, responseWriter, req.QName())

	// Export metric with the server label set to the current server handling the request.
	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Call next plugin (if any).
	return plugin.NextOrFailure(nat46.Name(), nat46.Next, ctx, pw, dnsMsg)
}

// Name implements the Handler interface.
func (nat46 Nat46) Name() string { return PluginName }

// requestShouldIntercept returns true if the request represents one that is eligible
// for NAT46 processing:
// 1. The request came in over IPv4
// 2. The request is of type A
// 3. The request is of class INET
// 4. The requested name matches one of the NAT46 domain prefixes
func (nat46 *Nat46) requestShouldIntercept(req *request.Request) bool {
	// Make sure that request came in over IPv4
	if req.Family() != 1 || req.QType() != dns.TypeA || req.QClass() != dns.ClassINET {
		log.Debugf("Ignore queries of this family (%d), type (%d) or class(%d)", req.Family(), req.QType(), req.QClass())
		return false
	}

	chunks := strings.Split(req.QName(), ".")
	slices.Reverse(chunks)
	log.Debugf("QName: %v", chunks)
	for _, nattedDomain := range nat46.domains {
		log.Debugf("Trying to match '%v'", nattedDomain)
		i := 0
		for _, chunk := range chunks {
			if chunk == "" {
				continue
			}
			if i >= len(nattedDomain) {
				break
			}
			log.Debugf("i: %d, chunk: '%s', nattedDomain[i]: %s", i, chunk, nattedDomain[i])
			if chunk != nattedDomain[i] {
				break
			}
			i++
		} //for
		if i >= len(nattedDomain) {
			log.Debug("Query matches, should NAT it")
			return true
		}
	} //for

	log.Debug("Query does not match any NATted domain, ignore it")
	return false
}

// ResponseInterceptor wrap a dns.ResponseWriter and performs additional processing
type ResponseInterceptor struct {
	nat46 Nat46
	dns.ResponseWriter
	domain string
}

// NewResponseInterceptor returns ResponseWriter.
func NewResponseInterceptor(nat46 Nat46, w dns.ResponseWriter, domain string) *ResponseInterceptor {
	return &ResponseInterceptor{nat46: nat46, ResponseWriter: w, domain: domain}
}

// WriteMsg performs additional processing and then calls the underlying ResponseWriter's WriteMsg method.
func (interceptor *ResponseInterceptor) WriteMsg(resp *dns.Msg) error {
	log.Debugf("Returned from the next plugin with the result: %v", resp)
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			chunks := regexp.MustCompile(`[\t ]+`).Split(rr.String(), -1)
			for i := 0; i < len(chunks); i++ {
				log.Debugf("RR[%d]: %s", i, chunks[i])
			} //for
			interceptor.nat46.setupNat(interceptor.domain, chunks[len(chunks)-1])
		}
	}

	return interceptor.ResponseWriter.WriteMsg(resp)
}

// Install NAT46 rule for the specified "domain => ipv4-address" pair
func (nat46 Nat46) setupNat(domain string, ipv4Addr string) {
	log.Debugf("Setting up NAT46 for '%s => %s'", domain, ipv4Addr)
}
