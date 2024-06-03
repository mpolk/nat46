package nat46

import (
	"bytes"
	"context"
	golog "log"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestNat46(t *testing.T) {
	// Create a new Nat46 Plugin. Use the test.ErrorHandler as the next plugin.
	x := Nat46{Next: test.ErrorHandler()}

	// Setup a new output buffer that is *not* standard output, so we can check if
	// example is really being printed.
	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("nat46.org.", dns.TypeA)
	// Create a new Recorder that captures the result, this isn't actually used in this test
	// as it just serves as something that implements the dns.ResponseWriter interface.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call our plugin directly, and check the result.
	x.ServeDNS(ctx, rec, r)
	if a := b.String(); !strings.Contains(a, "[INFO] plugin/nat46: nat46") {
		t.Errorf("Failed to print '%s', got %s", "[INFO] plugin/nat46: nat46", a)
	}
}
