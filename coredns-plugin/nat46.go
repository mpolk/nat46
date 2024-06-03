package nat46

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("nat46")

type Nat46 struct {
	Next plugin.Handler
}

// ServeDNS implements the plugin.Handler interface. This method gets called when nat46 is used
// in a Server.
func (this Nat46) ServeDNS(ctx context.Context, responseWriter dns.ResponseWriter, request *dns.Msg) (int, error) {
	// This function could be simpler. I.e. just fmt.Println("nat46") here, but we want to show
	// a slightly more complex example as to make this more interesting.
	// Here we wrap the dns.ResponseWriter in a new ResponseWriter and call the next plugin, when the
	// answer comes back, it will print "nat46".

	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	log.Info("Received response")

	// Wrap.
	pw := NewResponsePrinter(responseWriter)

	// Export metric with the server label set to the current server handling the request.
	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Call next plugin (if any).
	return plugin.NextOrFailure(this.Name(), this.Next, ctx, pw, request)
}

// Name implements the Handler interface.
func (this Nat46) Name() string { return "nat46" }

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
	log.Info("next plugin done")
	return r.ResponseWriter.WriteMsg(res)
}
