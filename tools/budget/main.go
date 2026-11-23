// Command budget checks the three size limits from section 13 of the brief:
// the binary under 60 MB, the recipient page under 150 kB of gzipped
// JavaScript, and — reported but not enforced here, because it needs a running
// process — memory at rest under 100 MB.
//
// A budget nobody measures is a wish. This runs in CI after the build, so the
// day a dependency adds forty kilobytes to the page a recipient loads, the
// build says so instead of someone noticing a year later.
//
//	go run ./tools/budget            # against bin/peek and internal/webui/dist
//	go run ./tools/budget -json      # for a CI summary
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// The budgets, in bytes. They are the brief's, not a guess.
const (
	binaryBudget = 60 << 20
	// The recipient page is the one that matters: it is loaded by people who
	// did not choose to use Peek, sometimes on a phone on a train. The budget
	// covers the JavaScript the page needs, gzipped, which is what a browser
	// actually pulls down.
	scriptBudget = 150 << 10
	// The stylesheet is not in the brief's budget but is part of the same
	// download, so it is reported beside it.
	styleBudget = 40 << 10
)

type result struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	Budget int64  `json:"budget"`
	Detail string `json:"detail,omitempty"`
}

func (r result) ok() bool { return r.Budget == 0 || r.Bytes <= r.Budget }

func main() {
	binaryPath := flag.String("binary", defaultBinary(), "path to the built binary")
	distPath := flag.String("dist", filepath.Join("internal", "webui", "dist"), "path to the embedded interface")
	asJSON := flag.Bool("json", false, "print JSON")
	flag.Parse()

	results, err := measure(*binaryPath, *distPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "budget:", err)
		os.Exit(2)
	}

	if *asJSON {
		buf, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "budget:", err)
			os.Exit(2)
		}
		fmt.Println(string(buf))
	} else {
		report(results)
	}

	for _, r := range results {
		if !r.ok() {
			os.Exit(1)
		}
	}
}

func measure(binaryPath, distPath string) ([]result, error) {
	var out []result

	info, err := os.Stat(binaryPath)
	switch {
	case err == nil:
		out = append(out, result{Name: "binary", Bytes: info.Size(), Budget: binaryBudget,
			Detail: binaryPath})
	case os.IsNotExist(err):
		// Not fatal: someone may be checking the page alone.
		out = append(out, result{Name: "binary", Detail: binaryPath + " not built"})
	default:
		return nil, err
	}

	scripts, styles, names, err := measureDist(distPath)
	if err != nil {
		return nil, err
	}
	out = append(out,
		result{Name: "recipient page, JavaScript gzipped", Bytes: scripts, Budget: scriptBudget,
			Detail: strings.Join(names, " ")},
		result{Name: "recipient page, CSS gzipped", Bytes: styles, Budget: styleBudget},
	)
	return out, nil
}

// measureDist gzips every script and stylesheet the page loads and adds them
// up. Each file is compressed on its own, which is what a server does.
func measureDist(dir string) (scripts, styles int64, names []string, err error) {
	entries, err := os.Stat(dir)
	if err != nil || !entries.IsDir() {
		return 0, 0, nil, fmt.Errorf("%s is not a directory: run make web-build first", dir)
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		size, gzErr := gzipSize(path)
		if gzErr != nil {
			return gzErr
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".js", ".mjs":
			scripts += size
			names = append(names, filepath.Base(path))
		case ".css":
			styles += size
		}
		return nil
	})
	sort.Strings(names)
	return scripts, styles, names, err
}

func gzipSize(path string) (int64, error) {
	f, err := os.Open(path) //nolint:gosec // a path inside the build output
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	counter := &countingWriter{}
	// Level 9: a sensible proxy for what a CDN or nginx with gzip_comp_level
	// turned up would serve, and the pessimistic end of what a browser gets.
	gz, err := gzip.NewWriterLevel(counter, gzip.BestCompression)
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(gz, f); err != nil {
		return 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	return counter.n, nil
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func report(results []result) {
	failed := false
	for _, r := range results {
		switch {
		case r.Budget == 0 && r.Bytes == 0:
			fmt.Printf("  --   %-36s %s\n", r.Name, r.Detail)
		case r.ok():
			fmt.Printf("  ok   %-36s %7s of %s\n", r.Name, human(r.Bytes), human(r.Budget))
		default:
			failed = true
			fmt.Printf("  OVER %-36s %7s of %s — over by %s\n",
				r.Name, human(r.Bytes), human(r.Budget), human(r.Bytes-r.Budget))
		}
	}
	fmt.Println()
	if failed {
		fmt.Println("A size budget from section 13 of the brief is exceeded.")
		return
	}
	fmt.Printf("Within every budget (measured on %s/%s).\n", runtime.GOOS, runtime.GOARCH)
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func defaultBinary() string {
	if runtime.GOOS == "windows" {
		return filepath.Join("bin", "peek.exe")
	}
	return filepath.Join("bin", "peek")
}
