package nat46

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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

const modControlFile = "/proc/net/nat46/control"

type Nat46 struct {
	Next            plugin.Handler
	domains         [][]string
	ipv6Prefix      net.IPNet
	nat46Device     string
	postInstallCmds []string
	upstream        UpstreamInt
}

func NewNat46(domainsFileName string, ipv6Prefix string, nat46Device string,
	postInstallCmds []string, upstream UpstreamInt) (*Nat46, error) {

	if nat46Device == "" {
		nat46Device = "nat46"
	}

	domains := [][]string{}
	if domainsFileName != "" {
		domainsFile, err := os.Open(domainsFileName)
		if err != nil {
			return nil, plugin.Error(PluginName, err)
		}

		log.Debugf("Reading domains from %s", domainsFileName)
		defer domainsFile.Close()
		scanner := bufio.NewScanner(domainsFile)
		for scanner.Scan() {
			domain := strings.Split(scanner.Text(), ".")
			slices.Reverse(domain)
			log.Debugf("nat46 domain: %v", domain)
			domains = append(domains, domain)
		}
	} //if

	if ipv6Prefix == "" {
		return nil, plugin.Error(PluginName, errors.New("IPv6 network specific prefix is not defined"))
	}
	_, prefix, err := net.ParseCIDR(ipv6Prefix)
	if err != nil {
		return nil, plugin.Error(PluginName, err)
	}
	log.Debugf("IPV6 prefix: %v", prefix)
	log.Debugf("NAT46 deivice: '%s'", nat46Device)

	return &Nat46{domains: domains, ipv6Prefix: *prefix, nat46Device: nat46Device,
		postInstallCmds: postInstallCmds, upstream: upstream}, nil
} //NewNat46

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
} //ServeDNS

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

	if len(nat46.domains) == 0 {
		log.Debug("Should NAT any domain, particularly this one")
		return true
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
} //requestShouldIntercept

// ResponseInterceptor wrap a dns.ResponseWriter and performs additional processing
type ResponseInterceptor struct {
	nat46           *Nat46
	ctx             context.Context
	originalRequest *dns.Msg
	dns.ResponseWriter
}

// NewResponseInterceptor returns ResponseWriter.
func NewResponseInterceptor(nat46 *Nat46,
	ctx context.Context,
	originalRequest *dns.Msg,
	w dns.ResponseWriter) *ResponseInterceptor {
	return &ResponseInterceptor{nat46: nat46, ctx: ctx, originalRequest: originalRequest, ResponseWriter: w}
} //NewResponseInterceptor

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
			ipv4Addr := chunks[len(chunks)-1]
			go interceptor.setupNat(ipv4Addr)
		}
	}

	return interceptor.ResponseWriter.WriteMsg(resp)
} //WriteMsg

// Install NAT46 rule for the specified "domain => ipv4-address" pair
func (i *ResponseInterceptor) setupNat(ipv4Addr string) {
	req := request.Request{W: i.ResponseWriter, Req: i.originalRequest}
	domain := req.QName()
	log.Debugf("About to setup NAT46 for '%s' (%s)", domain, ipv4Addr)
	resp, err := i.nat46.upstream.Lookup(i.ctx, req, req.Name(), dns.TypeAAAA)
	log.Debugf("Received response for the secondary query: %v", resp)
	if err != nil {
		log.Warningf("...failed to learn target IPv6 address, bailing out")
		return
	}
	ty, _ := response.Typify(resp, time.Now().UTC())
	if ty != response.NoError {
		log.Warningf("...failed to learn target IPv6 address, bailing out")
		return
	}

	ipv6Addr := ""
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			chunks := whitespace.Split(rr.String(), -1)
			ipv6Addr = chunks[len(chunks)-1]
			break
		} //if
	}

	if ipv6Addr == "" {
		return
	}

	log.Infof("Setting up NAT46 for '%s': %s => %s", domain, ipv4Addr, ipv6Addr)
	controlFile, err := os.OpenFile(modControlFile, os.O_RDWR, 0)
	if err != nil {
		log.Error("Cannot open NAT46 module control file!")
		return
	}

	defer controlFile.Close()
	natDevicePresent := false
	addDeviceCmd := fmt.Sprintf("add %s", i.nat46.nat46Device)
	insertCmdPattern := regexp.MustCompile(fmt.Sprintf("insert %s .* remote.v4 %s", i.nat46.nat46Device, ipv4Addr))
	localV6Pattern := regexp.MustCompile(fmt.Sprintf("local.v6 %s", &i.nat46.ipv6Prefix))
	remoteV6Pattern := regexp.MustCompile(fmt.Sprintf("remote.v6 %s", ipv6Addr))
	removeCmd := ""

	scanner := bufio.NewScanner(controlFile)
	for scanner.Scan() {
		line := scanner.Text()
		log.Debugf("control file: %s", line)
		if matches, _ := regexp.MatchString(addDeviceCmd, line); matches {
			natDevicePresent = true
			continue
		}
		if insertCmdPattern.MatchString(line) {
			if localV6Pattern.MatchString(line) && remoteV6Pattern.MatchString(line) {
				log.Debug("Rule already configured, won't do anything")
				return
			}
			removeCmd = strings.Replace(line, "insert", "remove", 1)
			continue
		}
	} //for

	if !natDevicePresent {
		log.Info(addDeviceCmd)
		fmt.Fprintln(controlFile, addDeviceCmd)
		cmd := fmt.Sprintf("ip link set dev %s up", i.nat46.nat46Device)
		log.Info(cmd)
		chunks := whitespace.Split(cmd, -1)
		err := exec.Command(chunks[0], chunks[1:]...).Run()
		if err != nil {
			plugin.Error(PluginName, err)
		} //if
	} //if

	if removeCmd != "" {
		log.Info(removeCmd)
		fmt.Fprintln(controlFile, removeCmd)
	} //if

	insertCmd := fmt.Sprintf("insert %s local.v6 %s local.style RFC6052 remote.v4 %s remote.v6 %s remote.style NONE",
		i.nat46.nat46Device, &i.nat46.ipv6Prefix, ipv4Addr, ipv6Addr)
	log.Info(insertCmd)
	fmt.Fprintln(controlFile, insertCmd)

	for _, cmdTemplate := range i.nat46.postInstallCmds {
		cmd := strings.ReplaceAll(cmdTemplate, "{ipv4}", ipv4Addr)
		cmd = strings.ReplaceAll(cmd, "{ipv6}", ipv6Addr)
		cmd = strings.ReplaceAll(cmd, "{nsp}", i.nat46.ipv6Prefix.String())
		cmd = strings.ReplaceAll(cmd, "{prefix}", i.nat46.ipv6Prefix.String())
		cmd = strings.ReplaceAll(cmd, "{device}", i.nat46.nat46Device)
		cmd = strings.ReplaceAll(cmd, "{nat46device}", i.nat46.nat46Device)
		log.Info(cmd)
		chunks := whitespace.Split(cmd, -1)
		err := exec.Command(chunks[0], chunks[1:]...).Run()
		if err != nil {
			plugin.Error(PluginName, err)
		} //if
	} //for
} //setupNat
