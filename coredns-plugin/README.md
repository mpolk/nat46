# nat46

## Name

*nat46* - prints "nat46" after a query is handled.

## Description

The nat46 plugin prints "nat46" on every query that got handled by the server. It serves as
documentation for writing CoreDNS plugins.

## Compilation

This package will always be compiled as part of CoreDNS and not in a standalone way. It will require you to use `go get` or as a dependency on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg).

The [manual](https://coredns.io/manual/toc/#what-is-coredns) will have more information about how to configure and extend the server with external plugins.

A simple way to consume this plugin, is by adding the following on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg), and recompile it as [detailed on coredns.io](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file).

~~~
example:github.com/coredns/example
~~~

Put this early in the plugin list, so that *nat46* is executed before any of the other plugins.

After this you can compile coredns by:

``` sh
go generate
go build
```

Or you can instead use make:

``` sh
make
```

## Syntax

~~~ txt
nat46
~~~

## Metrics

If monitoring is enabled (via the *prometheus* directive) the following metric is exported:

* `coredns_nat46_request_count_total{server}` - query count to the *nat46* plugin.

The `server` label indicated which server handled the request, see the *metrics* plugin for details.

## Ready

This plugin reports readiness to the ready plugin. It will be immediately ready.

## Examples

In this configuration, we forward all queries to 9.9.9.9 and print "nat46" whenever we receive
a query.

~~~ corefile
. {
  forward . 9.9.9.9
  nat46
}
~~~

Or without any external connectivity:

~~~ corefile
. {
  whoami
  nat46
}
~~~

## Also See

See the [manual](https://coredns.io/manual).
