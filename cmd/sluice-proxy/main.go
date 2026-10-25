// Command sluice-proxy runs the engine headless: a plain-HTTP forward proxy
// that logs one line per exchange. Usage:
//
//	sluice-proxy -listen 127.0.0.1:8080
//	curl -x http://127.0.0.1:8080 http://localhost:5000/
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dgtlmonk/sluice/internal/engine"
	"github.com/dgtlmonk/sluice/internal/live"
)

func main() {
	listen := flag.String("listen", engine.DefaultListenAddr, "listen address (loopback only unless -allow-non-loopback)")
	allowWide := flag.Bool("allow-non-loopback", false, "allow listening on a non-loopback address (exposes the proxy to the network)")
	flag.Parse()

	if err := run(*listen, *allowWide); err != nil {
		log.Fatal(err)
	}
}

func run(listen string, allowWide bool) error {
	ln, err := engine.Listen(listen, allowWide)
	if err != nil {
		return err
	}

	// The log line is written off the forwarding path through the same lossy
	// live feed the UI will use: a slow terminal can drop log lines (counted)
	// but never stalls traffic.
	feed := live.NewFeed[engine.Exchange](4096, 256)
	feedCtx, stopFeed := context.WithCancel(context.Background())
	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		feed.Run(feedCtx, 100*time.Millisecond, logBatch)
	}()

	cfg := engine.DefaultConfig()
	cfg.Events = feed
	srv := engine.NewServer(cfg)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.Printf("sluice-proxy listening on %s", ln.Addr())

	select {
	case err := <-serveErr:
		stopFeed()
		<-feedDone
		return err
	case <-sigCtx.Done():
	}

	log.Printf("shutting down (waiting up to 10s for in-flight exchanges)")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutErr := srv.Shutdown(shutCtx)
	if err := <-serveErr; err != nil && !errors.Is(err, engine.ErrServerClosed) {
		log.Printf("serve: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // one feed tick, so the last lines print
	stopFeed()
	<-feedDone
	if s := feed.Stats(); s.Dropped > 0 {
		log.Printf("live feed dropped %d log events", s.Dropped)
	}
	if shutErr != nil && !errors.Is(shutErr, context.DeadlineExceeded) {
		return shutErr
	}
	return nil
}

// logBatch prints method, host, path, status, bytes and duration only. The
// query string is cut from the path because tokens often travel there;
// headers and bodies are never logged (CLAUDE.md, Security).
func logBatch(batch []engine.Exchange) {
	for _, e := range batch {
		line := e.Method + " " + e.Host + " " + pathOnly(e.Path)
		if e.Err != "" {
			log.Printf("%s %d %dB %s err=%q", line, e.Status, e.RespBytes, e.Duration.Round(time.Millisecond), e.Err)
			continue
		}
		log.Printf("%s %d %dB %s", line, e.Status, e.RespBytes, e.Duration.Round(time.Millisecond))
	}
}

func pathOnly(p string) string {
	for i := 0; i < len(p); i++ {
		if p[i] == '?' {
			return p[:i]
		}
	}
	return p
}
