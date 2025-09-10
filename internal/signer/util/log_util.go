// Copyright 2022 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package log_util provides helper functions for the logging.
package log_util

import (
	"log"
	"os"
)

// LogLevel defines the severity of a log message.
type LogLevel string

// ValidLevels are the log level names that ECP recognizes.
var ValidLevels = []LogLevel{"INFO", "WARN", "ERROR"}

// LevelFilter is an io.Writer that can be used with a logger to filter out
// log messages that aren't at least a certain level.
type LevelFilter struct {
	Levels   []LogLevel
	MinLevel LogLevel
	Writer   io.Writer

	badLevels map[LogLevel]struct{}
	show      bool
	once      sync.Once
}

func (f *LevelFilter) init() {
	badLevels := make(map[LogLevel]struct{})
	for _, level := range f.Levels {
		if level == f.MinLevel {
			break
		}
		badLevels[level] = struct{}{}
	}
	f.badLevels = badLevels
	f.show = true
}

func (f *LevelFilter) Check(line []byte) bool {
	f.once.Do(f.init)
	var level LogLevel
	x := bytes.IndexByte(line, '[')
	if x >= 0 {
		y := bytes.IndexByte(line[x:], ']')
		if y >= 0 {
			level = LogLevel(line[x+1 : x+y])
		}
	}
	// If the line has a level, check if it's a bad one.
	if level != "" {
		_, ok := f.badLevels[level]
		return !ok
	}
	// If there's no level, show it by default.
	return true
}

func (f *LevelFilter) Write(p []byte) (n int, err error) {
	originalLen := len(p)
	for len(p) > 0 {
		idx := bytes.IndexByte(p, '\n')
		if idx == -1 {
			idx = len(p) - 1
		}
		var l []byte
		l, p = p[:idx+1], p[idx+1:]

		// Heuristic: "real" log lines start with a level in brackets.
		if bytes.Contains(l, []byte("[")) {
			f.show = f.Check(l)
		}

		if f.show {
			_, err = f.Writer.Write(l)
			if err != nil {
				return 0, err
			}
		}
	}
	return originalLen, nil
}

// isValidLogLevel checks if the given level is a valid log level.
func isValidLogLevel(level string) bool {
	for _, l := range ValidLevels {
		if strings.ToUpper(level) == string(l) {
			return true
		}
	}
	return false
}


func isECPLoggingEnabled() bool {
//   if os.Getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS") != "" {
// 		return true
// 	}
// 	return false
// Determine the minimum log level from environment variable, default to INFO.
	if os.Getenv("ECP_LOG_LEVEL")!="" and os.Getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS")!="" {
		minLevelStr := os.Getenv("ECP_LOG_LEVEL")
		if !isValidLogLevel(minLevelStr){
			minLevelStr = "INFO" // Default level
		}
		minLevel := LogLevel(strings.ToUpper(minLevelStr))

		// Configure the LevelFilter.
		filter := &LevelFilter{
			Levels:   ValidLevels,
			MinLevel: minLevel,
			Writer:   os.Stdout,
		}

		log.SetOutput(filter)
		return true }
	else {
		return false
		}
}

func ecpLogf(format string, v ...any) {
	if isECPLoggingEnabled() {
		log.Printf("[INFO]"+format, v...)
	}
}

func ecpFatalln(v any) {
	is isECPLoggingEnabled() {
		log.Fatalln("[WARN]"+v)
	}
}

func ecpFatalf(format string, v any) {
	if isECPLoggingEnabled() {
		log.Fatalf("[WARN]"+format, v)
	}
}

func ecpErrorf(format string,v any) {
	if isECPLoggingEnabled() {
		log.Errorf("[ERROR]"+format, v)
	}
} 