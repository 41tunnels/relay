// Command relay is the OpenCharUI relay server (spec/PROTOCOL.md). It
// wires internal/{config,hub,auth,limits,metrics,logging,server} together,
// serves the public WebSocket endpoints and a separate loopback-only
// metrics listener, and shuts down gracefully on SIGTERM/SIGINT.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/41tunnels/relay/internal/auth"
	"github.com/41tunnels/relay/internal/config"
	"github.com/41tunnels/relay/internal/hub"
	"github.com/41tunnels/relay/internal/limits"
	"github.com/41tunnels/relay/internal/logging"
	"github.com/41tunnels/relay/internal/metrics"
	"github.com/41tunnels/relay/internal/server"
)

// version is stamped at build time via -ldflags "-X main.version=..." (see
// Dockerfile); the release workflow passes the semantic-release version, so
// a running container can be traced back to the tag it was built from.
// Local `go build` leaves it "dev".
var version = "dev"

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe a locally running relay's /healthz and exit 0/1 (for Docker HEALTHCHECK — distroless has no shell/curl)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "relay: config error:", err)
		os.Exit(1)
	}

	if *healthcheck {
		os.Exit(runHealthcheck(cfg))
	}

	log := logging.New(cfg)

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	h := hub.New(cfg.MaxPairs, cfg.PairRateBytesPerSec)
	authz := auth.OpenAuthorizer{Default: auth.Grant{
		MaxBytesPerSec: cfg.PairRateBytesPerSec,
		MaxFrameBytes:  cfg.MaxFrameBytes,
		Tier:           "open",
	}}
	ipLim := limits.NewIPLimiter(cfg.IPConnPerMin)

	srv := server.New(cfg, h, authz, ipLim, m, log)

	metricsSrv := &http.Server{
		Addr:    cfg.MetricsAddr,
		Handler: promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
	}
	go func() {
		log.Info("metrics listening", "addr", cfg.MetricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("metrics server error", "err", err)
		}
	}()

	go ipLimiterJanitor(context.Background(), ipLim)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Info("relay listening", "addr", cfg.Addr, "max_pairs", cfg.MaxPairs, "version", version)
	if err := srv.Run(ctx); err != nil {
		log.Error("relay server error", "err", err)
		_ = metricsSrv.Shutdown(context.Background())
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = metricsSrv.Shutdown(shutdownCtx)
	log.Info("relay stopped")
}

// ipLimiterJanitor periodically sweeps stale per-IP rate-limit entries so
// a long-running process doesn't accumulate one bucket per distinct
// source IP forever (internal/limits.IPLimiter.Sweep's doc comment).
func ipLimiterJanitor(ctx context.Context, l *limits.IPLimiter) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Sweep(15 * time.Minute)
		}
	}
}

// runHealthcheck implements the Docker HEALTHCHECK entrypoint: GET
// /healthz on the loopback listener with a short timeout. distroless has
// no shell and no curl, so the binary has to probe itself.
func runHealthcheck(cfg config.Config) int {
	addr := cfg.Addr
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: bad RELAY_ADDR:", addr)
		return 1
	}
	if host == "" {
		host = "127.0.0.1"
	}
	url := fmt.Sprintf("http://%s:%s/healthz", host, port)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: request failed:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
