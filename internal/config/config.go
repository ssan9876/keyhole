// Package config loads the server's on-disk configuration.
//
// The format is a deliberately tiny subset of YAML — flat "key: value" lines
// and "#" comments. A real YAML parser would be a dependency we do not need for
// four settings, and the installer writes this file, so the surface is ours.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	// Addr is the local address the HTTP server binds. The tunnel connects to
	// it, so it should stay on loopback in production.
	Addr string
	// DataDir holds the SQLite database and the server secret.
	DataDir string
	// BaseURL is the externally reachable origin, used to build setup and
	// invite links. No trailing slash.
	BaseURL string
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
}

func Default() Config {
	return Config{
		Addr:     "127.0.0.1:8477",
		DataDir:  "/var/lib/keyhole",
		BaseURL:  "http://localhost:8477",
		LogLevel: "info",
	}
}

// DBPath is where the SQLite database lives for this configuration.
func (c Config) DBPath() string {
	return filepath.Join(c.DataDir, "keyhole.db")
}

// SecretPath is where the server secret lives. Written 0600 on first run.
func (c Config) SecretPath() string {
	return filepath.Join(c.DataDir, "server.secret")
}

// Load reads path over the defaults. A missing file is not an error: a fresh
// install with no config should start with sane values rather than refuse.
func Load(path string) (Config, error) {
	c := Default()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			return c, fmt.Errorf("config line %d: expected \"key: value\", got %q", lineNo, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "addr":
			c.Addr = value
		case "data_dir":
			c.DataDir = value
		case "base_url":
			c.BaseURL = strings.TrimRight(value, "/")
		case "log_level":
			c.LogLevel = value
		default:
			return c, fmt.Errorf("config line %d: unknown key %q", lineNo, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	return c, nil
}
