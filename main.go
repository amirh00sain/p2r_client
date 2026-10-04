package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Client binary name as shipped: spider-client
var version = "1.0.0"

func main() {
	var (
		configPath  = flag.String("config", "client.json", "path to the JSON configuration file")
		server      = flag.String("server", "", "override server url (wss://host/ws)")
		token       = flag.String("token", "", "override tunnel token")
		listen      = flag.String("listen", "", "override local SOCKS5 listen address (e.g. 127.0.0.1:1819)")
		verbose     = flag.Bool("verbose", false, "enable debug logging")
		checkOnly   = flag.Bool("check", false, "validate configuration and exit")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("spider-client %s\n", version)
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		// Allow running entirely from flags/env when the file is absent.
		if os.IsNotExist(err) || fileMissing(err) {
			cfg = &Config{
				HeartbeatInterval: 20 * time.Second,
				ReconnectMin:      time.Second,
				ReconnectMax:      30 * time.Second,
				MaxSessions:       512,
				EnableUDP:         true,
				EnableTCP:         true,
				OpenWait:          10 * time.Second,
				DialTimeout:       10 * time.Second,
			}
			if v := os.Getenv("SPIDER_SERVER"); v != "" {
				cfg.Server = v
			}
			if v := os.Getenv("SPIDER_TOKEN"); v != "" {
				cfg.Token = v
			}
			if v := os.Getenv("SPIDER_LISTEN"); v != "" {
				cfg.Listen = v
			}
			if cfg.Listen == "" {
				cfg.Listen = "127.0.0.1:1819"
			}
			if err := cfg.Validate(); err != nil {
				fatal(err)
			}
		} else {
			fatal(err)
		}
	}

	// Command-line flags win over both the file and the environment.
	if *server != "" {
		cfg.Server = *server
	}
	if *token != "" {
		cfg.Token = *token
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *verbose {
		cfg.Verbose = true
	}
	if err := cfg.Validate(); err != nil {
		fatal(err)
	}

	if *checkOnly {
		fmt.Printf("configuration OK\n  server:      %s\n  token:       %s…\n  listen:      %s\n  heartbeat:   %s\n  max_sessions: %d\n  udp:         %v\n",
			cfg.Server, maskToken(cfg.Token), cfg.Listen,
			cfg.HeartbeatInterval, cfg.MaxSessions, cfg.EnableUDP)
		return
	}

	log, err := NewLogger(cfg.Verbose, cfg.LogFile)
	if err != nil {
		fatal(err)
	}
	defer log.Close()

	log.Infof("spider-client %s starting", version)
	log.Infof("server:   %s", cfg.Server)
	log.Infof("token:    %s", maskToken(cfg.Token))
	log.Infof("socks5:   %s", cfg.Listen)
	log.Infof("heartbeat: %s, reconnect backoff %s…%s", cfg.HeartbeatInterval, cfg.ReconnectMin, cfg.ReconnectMax)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for a clean shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Infof("received %s, shutting down…", sig)
		cancel()
	}()

	tun := NewTunnel(cfg, log)
	go tun.Run(ctx)

	socks := NewSOCKS5Server(cfg, tun, log)
	if err := socks.Listen(); err != nil {
		fatal(err)
	}
	log.Infof("SOCKS5 listening on %s — point your browser/app here", socks.Addr())

	// Serve in a goroutine so the signal handler can exit the process.
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- socks.Serve(ctx)
	}()

	// Periodic status line.
	status := time.NewTicker(30 * time.Second)
	defer status.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Infof("shutdown complete (%s)", tun)
			time.Sleep(150 * time.Millisecond) // let in-flight logs flush
			return
		case err := <-serveErr:
			if ctx.Err() != nil {
				return
			}
			fatal(fmt.Errorf("socks5 server: %w", err))
		case <-status.C:
			state := "DOWN"
			if tun.IsReady() {
				state = "UP"
			}
			log.Infof("status: tunnel=%s sessions=%d opened=%d closed=%d",
				state, tun.SessionCount(), tun.OpenCount(), tun.CloseCount())
		}
	}
}

// fileMissing reports whether err came from a missing config file.
func fileMissing(err error) bool {
	return err != nil && os.IsNotExist(err)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[spider-client] %v\n", err)
	os.Exit(1)
}

// bufferSize / maxUDPPacket expose transport tuning to session code.
func (c *Config) bufferSize() int {
	const defaultBuf = 32 * 1024
	return defaultBuf
}

func (c *Config) maxUDPPacket() int {
	const maxPacket = 64 * 1024
	if c.MaxSessions > maxPacket {
		return maxPacket
	}
	return maxPacket
}
