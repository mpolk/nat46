package nat46

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
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
		log.Infof("nat46 domain: %v", domain)
		domains = append(domains, domain)
	}

	_, prefix, err := net.ParseCIDR(ipv6Prefix)
	if err != nil {
		return Nat46{}, plugin.Error(PluginName, err)
	}
	log.Infof("IPV6 prefix: %v", prefix)
	log.Infof("NAT46 deivice: '%s'", nat46Device)

	return Nat46{domains: domains, ipv6Prefix: *prefix, nat46Device: nat46Device, upstream: upstream}, nil
}

// ServeDNS implements the plugin.Handler interface. This method gets called when nat46 is used
// in a Server.
func (nat46 Nat46) ServeDNS(ctx context.Context, responseWriter dns.ResponseWriter, request *dns.Msg) (int, error) {
	// This function could be simpler. I.e. just fmt.Println("nat46") here, but we want to show
	// a slightly more complex example as to make this more interesting.
	// Here we wrap the dns.ResponseWriter in a new ResponseWriter and call the next plugin, when the
	// answer comes back, it will print "nat46".

	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	log.Info(fmt.Sprintf("Received request: %v", request.Question))

	// Wrap.
	pw := NewResponsePrinter(responseWriter)

	// Export metric with the server label set to the current server handling the request.
	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Call next plugin (if any).
	return plugin.NextOrFailure(nat46.Name(), nat46.Next, ctx, pw, request)
}

// Name implements the Handler interface.
func (nat46 Nat46) Name() string { return PluginName }

// ResponsePrinter wrap a dns.ResponseWriter and will write nat46 to standard output when WriteMsg is called.
type ResponsePrinter struct {
	dns.ResponseWriter
}

// NewResponsePrinter returns ResponseWriter.
func NewResponsePrinter(w dns.ResponseWriter) *ResponsePrinter {
	return &ResponsePrinter{ResponseWriter: w}
}

// WriteMsg calls the underlying ResponseWriter's WriteMsg method and prints "nat46" to standard output.
func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	log.Info("return from the next plugin")
	return r.ResponseWriter.WriteMsg(res)
}
