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
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/response"
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

var whitespace = regexp.MustCompile(`[\t ]+`)

type Nat46 struct {
	Next        plugin.Handler
	domains     [][]string
	ipv6Prefix  net.IPNet
	nat46Device string
	upstream    UpstreamInt
}

func NewNat46(domainsFileName string, ipv6Prefix string, nat46Device string, upstream UpstreamInt) (*Nat46, error) {
	domainsFile, err := os.Open(domainsFileName)
	if err != nil {
		return nil, plugin.Error(PluginName, err)
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
		return nil, plugin.Error(PluginName, err)
	}
	log.Debugf("IPV6 prefix: %v", prefix)
	log.Debugf("NAT46 deivice: '%s'", nat46Device)

	return &Nat46{domains: domains, ipv6Prefix: *prefix, nat46Device: nat46Device, upstream: upstream}, nil
}

// ServeDNS implements the plugin.Handler interface. This method gets called when nat46 is used
// in a Server.
func (nat46 Nat46) ServeDNS(ctx context.Context, responseWriter dns.ResponseWriter, reqMsg *dns.Msg) (int, error) {
	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	log.Debugf(fmt.Sprintf("Received request: %v", reqMsg.Question))

	// Don't proxy if we don't need to.
	req := request.Request{W: responseWriter, Req: reqMsg}
	if !nat46.requestShouldIntercept(&req) {
		return nat46.Next.ServeDNS(ctx, responseWriter, reqMsg)
	}

	// Wrap.
	pw := NewResponseInterceptor(&nat46, ctx, reqMsg, responseWriter)

	// Export metric with the server label set to the current server handling the request.
	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Call next plugin (if any).
	return plugin.NextOrFailure(nat46.Name(), nat46.Next, ctx, pw, reqMsg)
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

// Install NAT46 rule for the specified "domain => ipv4-address" pair
func (nat46 Nat46) setupNat(interceptor *ResponseInterceptor, ipv4Addr string) {
	req := request.Request{W: interceptor.ResponseWriter, Req: interceptor.originalRequest}
	domain := req.QName()
	log.Debugf("About to setup NAT46 for '%s' (%s)", domain, ipv4Addr)
	resp, err := nat46.upstream.Lookup(interceptor.ctx, req, req.Name(), dns.TypeAAAA)
	log.Debugf("Received response for the secondary query: %v", resp)
	if err != nil {
		log.Debugf("...failed to learn target IPv6 address, bailing out")
		return
	}

	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			chunks := whitespace.Split(rr.String(), -1)
			for i := 0; i < len(chunks); i++ {
				log.Debugf("RR[%d]: %s", i, chunks[i])
			} //for
			ipv6Addr := chunks[len(chunks)-1]
			log.Infof("Setting up NAT46 for '%s': %s => %s", domain, ipv4Addr, ipv6Addr)
		}
	}
}

// ResponseInterceptor wrap a dns.ResponseWriter and performs additional processing
type ResponseInterceptor struct {
	nat46           *Nat46
	ctx             context.Context
	originalRequest *dns.Msg
	dns.ResponseWriter
}

// NewResponseInterceptor returns ResponseWriter.
func NewResponseInterceptor(nat46 *Nat46, ctx context.Context, originalRequest *dns.Msg, w dns.ResponseWriter) *ResponseInterceptor {
	return &ResponseInterceptor{nat46: nat46, ctx: ctx, originalRequest: originalRequest, ResponseWriter: w}
}

// WriteMsg performs additional processing and then calls the underlying ResponseWriter's WriteMsg method.
func (interceptor *ResponseInterceptor) WriteMsg(resp *dns.Msg) error {
	log.Debugf("Returned from the next plugin with the result: %v", resp)
	ty, _ := response.Typify(resp, time.Now().UTC())
	if ty != response.NoError {
		return nil
	}

	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			chunks := whitespace.Split(rr.String(), -1)
			for i := 0; i < len(chunks); i++ {
				log.Debugf("RR[%d]: %s", i, chunks[i])
			} //for
			ipv4Address := chunks[len(chunks)-1]
			go interceptor.nat46.setupNat(interceptor, ipv4Address)
		}
	}

	return interceptor.ResponseWriter.WriteMsg(resp)
}
