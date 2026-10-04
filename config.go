package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the JSON configuration file (client.json) plus env overrides.
type Config struct {
	// Server is the WSS endpoint, e.g. "wss://example.up.railway.app/ws".
	Server string `json:"server"`
	// Token authenticates against TOKEN on the server.
	Token string `json:"token"`
	// Listen is the local SOCKS5 bind address, e.g. "127.0.0.1:1819".
	Listen string `json:"listen"`

	// HeartbeatInterval is how often a PING is sent (default 20s).
	HeartbeatInterval time.Duration `json:"-"`
	// ReconnectMin/Max bound the exponential backoff between dials.
	ReconnectMin time.Duration `json:"-"`
	ReconnectMax time.Duration `json:"-"`

	MaxSessions    int  `json:"max_sessions"`
	EnableUDP      bool `json:"udp_enabled"`
	EnableTCP      bool `json:"tcp_enabled"`
	InsecureSkipTLS bool `json:"insecure_skip_tls"`
	Verbose        bool `json:"verbose"`

	LogFile   string        `json:"log_file"`
	OpenWait  time.Duration `json:"-"`
	DialTimeout time.Duration `json:"-"`

	// JSON knobs arrive as numbers of seconds (or Go duration strings).
	Raw rawConfig `json:"-"`
}

// rawConfig holds the loosely-typed JSON representation so we can accept both
// numbers (seconds) and duration strings ("20s").
type rawConfig struct {
	HeartbeatInterval any `json:"heartbeat_interval"`
	ReconnectMin      any `json:"reconnect_min"`
	ReconnectMax      any `json:"reconnect_max"`
	OpenWait          any `json:"open_timeout"`
	DialTimeout       any `json:"dial_timeout"`
}

// LoadConfig reads client.json (or an alternative path) and applies
// environment overrides: SPIDER_SERVER, SPIDER_TOKEN, SPIDER_LISTEN.
func LoadConfig(path string) (*Config, error) {
	c := &Config{
		Listen:          "127.0.0.1:1819",
		HeartbeatInterval: 20 * time.Second,
		ReconnectMin:    1 * time.Second,
		ReconnectMax:    30 * time.Second,
		MaxSessions:     512,
		EnableUDP:       true,
		EnableTCP:       true,
		OpenWait:        10 * time.Second,
		DialTimeout:     10 * time.Second,
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &c.Raw); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		if err := decodeConfig(data, c); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		applyRaw(c)
	}

	// Environment always wins so secrets need not live on disk.
	if v := os.Getenv("SPIDER_SERVER"); v != "" {
		c.Server = v
	}
	if v := os.Getenv("SPIDER_TOKEN"); v != "" {
		c.Token = v
	}
	if v := os.Getenv("SPIDER_LISTEN"); v != "" {
		c.Listen = v
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// decodeConfig unmarshals twice: once into the typed fields, once into raw.
func decodeConfig(data []byte, c *Config) error {
	var plain struct {
		Server          string `json:"server"`
		Token           string `json:"token"`
		Listen          string `json:"listen"`
		MaxSessions     int    `json:"max_sessions"`
		EnableUDP       *bool  `json:"udp_enabled"`
		EnableTCP       *bool  `json:"tcp_enabled"`
		InsecureSkipTLS bool   `json:"insecure_skip_tls"`
		Verbose         bool   `json:"verbose"`
		LogFile         string `json:"log_file"`
	}
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	if plain.Server != "" {
		c.Server = plain.Server
	}
	if plain.Token != "" {
		c.Token = plain.Token
	}
	if plain.Listen != "" {
		c.Listen = plain.Listen
	}
	if plain.MaxSessions > 0 {
		c.MaxSessions = plain.MaxSessions
	}
	if plain.EnableUDP != nil {
		c.EnableUDP = *plain.EnableUDP
	}
	if plain.EnableTCP != nil {
		c.EnableTCP = *plain.EnableTCP
	}
	c.InsecureSkipTLS = plain.InsecureSkipTLS
	c.Verbose = plain.Verbose
	c.LogFile = plain.LogFile
	return nil
}

func applyRaw(c *Config) {
	if d, ok := parseDur(c.Raw.HeartbeatInterval); ok && d > 0 {
		c.HeartbeatInterval = d
	}
	if d, ok := parseDur(c.Raw.ReconnectMin); ok && d > 0 {
		c.ReconnectMin = d
	}
	if d, ok := parseDur(c.Raw.ReconnectMax); ok && d > 0 {
		c.ReconnectMax = d
	}
	if d, ok := parseDur(c.Raw.OpenWait); ok && d > 0 {
		c.OpenWait = d
	}
	if d, ok := parseDur(c.Raw.DialTimeout); ok && d > 0 {
		c.DialTimeout = d
	}
}

// parseDur accepts "30s", 30 (seconds) or 30.5 (seconds).
func parseDur(v any) (time.Duration, bool) {
	switch t := v.(type) {
	case nil:
		return 0, false
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, false
		}
		if d, err := time.ParseDuration(s); err == nil {
			return d, true
		}
		return 0, false
	case float64:
		return time.Duration(t * float64(time.Second)), true
	case int:
		return time.Duration(t) * time.Second, true
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return time.Duration(f * float64(time.Second)), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// Validate performs sanity checks before anything is dialled.
func (c *Config) Validate() error {
	if c.Server == "" {
		return fmt.Errorf(`config error: "server" is required (e.g. "wss://example.com/ws")`)
	}
	if !strings.HasPrefix(c.Server, "ws://") && !strings.HasPrefix(c.Server, "wss://") {
		return fmt.Errorf(`config error: "server" must start with ws:// or wss://, got %q`, c.Server)
	}
	if c.Token == "" {
		return fmt.Errorf(`config error: "token" is required (see the web panel)`)
	}
	if len(c.Token) < 8 {
		return fmt.Errorf("config error: token looks too short (%d chars)", len(c.Token))
	}
	if c.Listen == "" {
		return fmt.Errorf(`config error: "listen" is required (e.g. "127.0.0.1:1819")`)
	}
	if c.MaxSessions < 1 {
		c.MaxSessions = 512
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 20 * time.Second
	}
	if c.ReconnectMin <= 0 {
		c.ReconnectMin = time.Second
	}
	if c.ReconnectMax < c.ReconnectMin {
		c.ReconnectMax = c.ReconnectMin
	}
	if c.MaxSessions > 65000 {
		return fmt.Errorf("config error: max_sessions %d is too high (max 65000)", c.MaxSessions)
	}
	return nil
}
