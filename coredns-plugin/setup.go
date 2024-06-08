package nat46

import (
	"path/filepath"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/upstream"
)

const PluginName = "nat46"

// init registers this plugin.
func init() { plugin.Register(PluginName, setup) }

// setup is the function that gets called when the config parser see the token "nat46". Setup is responsible
// for parsing any extra options the nat46 plugin may have. The first token this function sees is "nat46".
func setup(c *caddy.Controller) error {
	config := dnsserver.GetConfig(c)
	nat46Device := ""
	domainsFileName := ""
	ipv6Prefix := ""
	postInstallCmds := []string{}

	c.Next() // Ignore "nat46" and give us the next token.
	for c.NextBlock() {
		switch c.Val() {
		case "domains":
			if !c.NextArg() {
				return c.ArgErr()
			}
			domainsFileName = c.Val()
			log.Debugf("domainsFileName: '%s'", domainsFileName)
			if !filepath.IsAbs(domainsFileName) {
				confDir := filepath.Dir(c.File())
				domainsFileName = filepath.Clean(filepath.Join(confDir, domainsFileName))
				log.Debugf("domainsFileName: '%s'", domainsFileName)
			}

		case "prefix":
			fallthrough
		case "nsp":
			if !c.NextArg() {
				return plugin.Error(PluginName, c.ArgErr())
			}
			ipv6Prefix = c.Val()
			log.Debugf("ipv6Prefix: '%s'", ipv6Prefix)

		case "device":
			if !c.NextArg() {
				return plugin.Error(PluginName, c.ArgErr())
			}
			nat46Device = c.Val()
			log.Debugf("nat46Device: '%s'", nat46Device)

		case "postinstall":
			fallthrough
		case "post-install":
			cmd := strings.Join(c.RemainingArgs(), " ")
			postInstallCmds = append(postInstallCmds, cmd)

		default:
			return plugin.Error(PluginName, c.Errf("unknown property '%s'", c.Val()))
		} //switch
	} //for

	nat46, err := NewNat46(domainsFileName, ipv6Prefix, nat46Device, postInstallCmds, upstream.New())
	if err != nil {
		return plugin.Error(PluginName, err)
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		nat46.Next = next
		return nat46
	})

	// All OK, return a nil error.
	return nil
}
