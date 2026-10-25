// Command sluice-load sends a fixed request mix (see internal/loadgen)
// through a running Sluice proxy to an internal/testorigin server, then
// prints throughput and latency. It is for watching the UI under load.
//
//	sluice-load -proxy 127.0.0.1:8081 -n 10000 -c 32
//
// With no -origin it starts its own testorigin on 127.0.0.1 (random port)
// and prints the address. Both addresses must be loopback: this tool never
// sends traffic off the machine.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/dgtlmonk/sluice/internal/loadgen"
	"github.com/dgtlmonk/sluice/internal/testorigin"
)

func main() {
	proxy := flag.String("proxy", "127.0.0.1:8080", "Sluice proxy address (loopback)")
	origin := flag.String("origin", "", "testorigin address (loopback); empty starts one in-process")
	n := flag.Int("n", 10_000, "total requests")
	c := flag.Int("c", 32, "concurrent clients")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	flag.Parse()

	if err := run(*proxy, *origin, *n, *c, *timeout); err != nil {
		log.Fatal(err)
	}
}

func run(proxy, origin string, n, c int, timeout time.Duration) error {
	for _, a := range []string{proxy, origin} {
		if a != "" && !isLoopback(a) {
			return fmt.Errorf("%s is not a loopback host:port", a)
		}
	}
	if origin == "" {
		addr, stop := testorigin.Start()
		defer stop()
		origin = addr
		log.Printf("started testorigin on %s", origin)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	log.Printf("sending %d requests via proxy %s to %s with %d clients", n, proxy, origin, c)
	res, err := loadgen.Run(ctx, loadgen.Config{Proxy: proxy, Origin: origin, N: n, Concurrency: c, Timeout: timeout})
	if err != nil {
		return err
	}
	fmt.Println(res)
	fmt.Println("by kind:", res.ByKind)
	if res.Failed > 0 {
		return errors.Join(fmt.Errorf("%d requests failed", res.Failed), res.FirstErr)
	}
	return nil
}

func isLoopback(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	// Only IP literals: "localhost" could be pointed off-machine by a
	// hosts-file entry, so it is not trusted by name.
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
