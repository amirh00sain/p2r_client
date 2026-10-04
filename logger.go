package main

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Logger emits timestamped client-side lines to stdout (and optionally a log
// file) so the user can watch connection, session and reconnect events.
type Logger struct {
	mu      sync.Mutex
	out     io.Writer
	file    *os.File
	verbose bool
	prefix  string
}

// NewLogger builds a logger. When logPath is non-empty the output is teed to
// that file as well.
func NewLogger(verbose bool, logPath string) (*Logger, error) {
	l := &Logger{out: os.Stdout, verbose: verbose, prefix: "spider-client"}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		l.file = f
	}
	return l, nil
}

// Close releases the log file handle.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}

func (l *Logger) logf(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %-5s [%s] %s\n",
		time.Now().Format("15:04:05"), level, l.prefix, msg)
	if l.out != nil {
		_, _ = io.WriteString(l.out, line)
	}
	if l.file != nil {
		_, _ = io.WriteString(l.file, line)
	}
}

// Debugf logs at DEBUG (only shown with -verbose).
func (l *Logger) Debugf(format string, args ...any) {
	if l.verbose {
		l.logf("DEBUG", format, args...)
	}
}

// Infof logs at INFO.
func (l *Logger) Infof(format string, args ...any) { l.logf("INFO", format, args...) }

// Warnf logs at WARN.
func (l *Logger) Warnf(format string, args ...any) { l.logf("WARN", format, args...) }

// Errorf logs at ERROR.
func (l *Logger) Errorf(format string, args ...any) { l.logf("ERROR", format, args...) }
