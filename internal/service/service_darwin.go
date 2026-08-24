//go:build darwin

package service

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// launchd distinguishes agents from daemons, and the difference matters here.
// A LaunchAgent runs as the logged-in user and only while someone is logged in;
// a LaunchDaemon runs as root from boot with no session. A background updater
// generally wants the daemon, but installing one requires administrative
// rights, so the per-user agent is the default.
func install(cfg Config) error {
	path, err := plistPath(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}
	if cfg.LogDir != "" {
		if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
			return fmt.Errorf("create log directory: %w", err)
		}
	}
	if err := os.WriteFile(path, []byte(plist(cfg)), 0o644); err != nil {
		return fmt.Errorf("write plist %s: %w", path, err)
	}

	// bootout first so that reinstalling over an existing registration is not
	// an error. The job is very likely absent, so its failure is ignored.
	target := domain(cfg)
	_ = runCommand("launchctl", "bootout", target+"/"+cfg.Name)

	if err := runCommand("launchctl", "bootstrap", target, path); err != nil {
		return err
	}
	return runCommand("launchctl", "enable", target+"/"+cfg.Name)
}

func uninstall(cfg Config) error {
	path, err := plistPath(cfg)
	if err != nil {
		return err
	}
	_ = runCommand("launchctl", "bootout", domain(cfg)+"/"+cfg.Name)

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist %s: %w", path, err)
	}
	return nil
}

func describe(cfg Config) string {
	path, err := plistPath(cfg)
	if err != nil {
		path = "(unresolved)"
	}
	kind := "LaunchAgent (runs as you, while logged in)"
	if cfg.System {
		kind = "LaunchDaemon (runs as root, from boot)"
	}
	return fmt.Sprintf("%s at %s", kind, path)
}

// plist renders the job definition.
//
// KeepAlive with SuccessfulExit=false is the launchd equivalent of systemd's
// Restart=always for this purpose: the program exits 0 after staging an update,
// and launchd must bring it back so the shim can install it. Without this the
// staged update would sit on disk forever.
func plist(cfg Config) string {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")

	writeKeyString(&b, "Label", cfg.Name)

	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, arg := range append([]string{cfg.Program}, cfg.Args...) {
		fmt.Fprintf(&b, "    <string>%s</string>\n", escape(arg))
	}
	b.WriteString("  </array>\n")

	if len(cfg.Env) > 0 {
		b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
		for _, kv := range cfg.Env {
			key, value, _ := strings.Cut(kv, "=")
			fmt.Fprintf(&b, "    <key>%s</key>\n    <string>%s</string>\n", escape(key), escape(value))
		}
		b.WriteString("  </dict>\n")
	}

	b.WriteString("  <key>RunAtLoad</key>\n  <true/>\n")
	b.WriteString("  <key>KeepAlive</key>\n  <dict>\n")
	b.WriteString("    <key>SuccessfulExit</key>\n    <false/>\n")
	b.WriteString("  </dict>\n")
	b.WriteString("  <key>ThrottleInterval</key>\n  <integer>5</integer>\n")

	if cfg.LogDir != "" {
		writeKeyString(&b, "StandardOutPath", filepath.Join(cfg.LogDir, cfg.Name+".out.log"))
		writeKeyString(&b, "StandardErrorPath", filepath.Join(cfg.LogDir, cfg.Name+".err.log"))
	}

	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func writeKeyString(b *strings.Builder, key, value string) {
	fmt.Fprintf(b, "  <key>%s</key>\n  <string>%s</string>\n", escape(key), escape(value))
}

func escape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func plistPath(cfg Config) (string, error) {
	if cfg.System {
		return filepath.Join("/Library/LaunchDaemons", cfg.Name+".plist"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", cfg.Name+".plist"), nil
}

func domain(cfg Config) string {
	if cfg.System {
		return "system"
	}
	return fmt.Sprintf("gui/%d", os.Getuid())
}
