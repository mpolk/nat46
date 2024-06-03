package nat46

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// init registers this plugin.
func init() { plugin.Register("nat46", setup) }

// setup is the function that gets called when the config parser see the token "nat46". Setup is responsible
// for parsing any extra options the nat46 plugin may have. The first token this function sees is "nat46".
func setup(c *caddy.Controller) error {
	c.Next() // Ignore "nat46" and give us the next token.
	if c.NextArg() {
		// If there was another token, return an error, because we don't have any configuration.
		// Any errors returned from this setup function should be wrapped with plugin.Error, so we
		// can present a slightly nicer error message to the user.
		return plugin.Error("nat46", c.ArgErr())
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Nat46{Next: next}
	})

	// All OK, return a nil error.
	return nil
}
