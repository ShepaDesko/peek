package config

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Duration is a time.Duration that reads and writes as a TOML string such as
// "30s", "24h" or "30d". go-toml has no native support for durations, and
// nanosecond integers in a hand-edited configuration file would be unkind.
type Duration time.Duration

// Std returns the standard library value.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) String() string {
	days := time.Duration(d) / (24 * time.Hour)
	if days > 0 && time.Duration(d)%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(days), 10) + "d"
	}
	return time.Duration(d).String()
}

// UnmarshalText accepts Go duration syntax plus a "d" (day) suffix.
func (d *Duration) UnmarshalText(text []byte) error {
	s := string(text)
	if s == "" {
		return errors.New("empty duration")
	}
	if n := len(s); s[n-1] == 'd' {
		days, err := strconv.ParseFloat(s[:n-1], 64)
		if err != nil {
			return fmt.Errorf("invalid duration %q", s)
		}
		*d = Duration(time.Duration(days * 24 * float64(time.Hour)))
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q (use forms like 45s, 30m, 12h, 7d)", s)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalText renders the duration as a readable string.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Days builds a Duration from a number of days.
func Days(n int) Duration { return Duration(time.Duration(n) * 24 * time.Hour) }

// Secs builds a Duration from a number of seconds.
func Secs(n int) Duration { return Duration(time.Duration(n) * time.Second) }
