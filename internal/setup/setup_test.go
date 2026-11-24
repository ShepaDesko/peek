package setup

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ShepaDesko/peek/internal/config"
)

// A configuration somewhere other than /etc/peek describes a self-contained
// instance.
//
// This is the whole of the bug it fixes: `peek setup --config <somewhere>` as
// an ordinary user wrote the file it was asked for, then tried to create the
// master key at the package default and failed on "mkdir /etc/peek:
// permission denied" — leaving a configuration behind that named a key which
// does not exist. Nothing the operator could pass reached that path.
func TestSetupOutsideEtcRootsEverythingBesideTheConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peek.toml")

	res, err := Run(Options{
		ConfigPath:     path,
		NonInteractive: true,
		Force:          true,
		In:             strings.NewReader(""),
		Out:            io.Discard,
		PublicURL:      "http://127.0.0.1:8080",
		Mode:           "internal",
		InternalListen: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("setup refused a configuration outside /etc/peek: %v", err)
	}

	// The key is beside the file that names it, and it is really there.
	wantKey := filepath.ToSlash(filepath.Join(dir, "master.key"))
	if res.Config.MasterKeyFile != wantKey {
		t.Errorf("master_key_file = %q, want %q", res.Config.MasterKeyFile, wantKey)
	}
	if _, err := os.Stat(res.MasterKeyPath); err != nil {
		t.Errorf("the master key was not written: %v", err)
	}

	// And so is everything else that was a /var default.
	for _, c := range []struct {
		name, got, want string
	}{
		{"data_dir", res.Config.DataDir, filepath.ToSlash(dir)},
		{"database.dsn", res.Config.Database.DSN, filepath.ToSlash(filepath.Join(dir, "peek.db"))},
		{"storage.path", res.Config.Storage.Path, filepath.ToSlash(filepath.Join(dir, "files"))},
		{"backup.dir", res.Config.Backup.Dir, filepath.ToSlash(filepath.Join(dir, "backups"))},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	// Nothing may point back into the packaged tree, which is the failure
	// this test exists to catch however it comes back.
	written, err := os.ReadFile(path) //nolint:gosec // G304: a path this test made
	if err != nil {
		t.Fatal(err)
	}
	for _, packaged := range []string{"/etc/peek", "/var/lib/peek", "/var/backups/peek"} {
		if strings.Contains(string(written), packaged) {
			t.Errorf("the written configuration still points at %s:\n%s", packaged, written)
		}
	}
}

// A flag the operator passes wins over the directory of the configuration.
func TestSetupKeepsWhatTheOperatorChose(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "ailleurs")

	res, err := Run(Options{
		ConfigPath:     filepath.Join(dir, "peek.toml"),
		NonInteractive: true,
		Force:          true,
		In:             strings.NewReader(""),
		Out:            io.Discard,
		PublicURL:      "http://127.0.0.1:8080",
		Mode:           "internal",
		InternalListen: "127.0.0.1:8080",
		DataDir:        data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.DataDir != data {
		t.Errorf("data_dir = %q, want the directory the operator passed, %q", res.Config.DataDir, data)
	}
}

// The packaged path keeps the packaged layout: an instance installed from the
// .deb must not move its key or its data because of this.
func TestPackagedPathIsUntouched(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the packaged layout is a Linux path")
	}
	cfg := config.Default()
	rootBeside(&cfg, config.DefaultPath)

	if cfg.MasterKeyFile != config.DefaultMasterKeyFile {
		t.Errorf("master_key_file moved to %q", cfg.MasterKeyFile)
	}
	if cfg.DataDir != config.Default().DataDir {
		t.Errorf("data_dir moved to %q", cfg.DataDir)
	}
}
