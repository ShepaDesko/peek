// Starts the built binary with a throwaway configuration and database.
//
// Everything lives under .e2e/, which is wiped on each run so a suite never
// inherits a secret from the previous one.
import { spawn } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const port = process.argv[2] ?? "8099";
const work = join(here, ".e2e");

rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });

const configPath = join(work, "peek.toml");
writeFileSync(
  configPath,
  `public_url = "http://127.0.0.1:${port}"
default_language = "fr"
master_key_file = ${JSON.stringify(join(work, "master.key"))}
data_dir = ${JSON.stringify(work)}
update_check = false

[server]
internal_listen = "127.0.0.1:${port}"
public_listen = "127.0.0.1:${Number(port) + 1}"

[database]
driver = "sqlite"
dsn = ${JSON.stringify(join(work, "peek.db"))}

[storage]
backend = "local"
path = ${JSON.stringify(join(work, "files"))}

[security]
anonymous_create = true
max_passphrase_attempts = 3

[security.rate_read]
burst = 0

[security.rate_api]
burst = 0

[security.rate_create]
burst = 0

# The suite signs in dozens of times; the login bucket is covered by the Go
# tests, and throttling it here would only make the suite flaky.
[security.rate_login]
burst = 0

[branding]
service_name = "Coffre E2E"
primary_color = "#1d4ed8"

[backup]
enabled = false
dir = ${JSON.stringify(join(work, "backups"))}

[log]
level = "warn"
format = "text"
`,
);

writeFileSync(join(work, "master.key"), Buffer.alloc(32, 7));

const binary = join(root, "bin", process.platform === "win32" ? "peek.exe" : "peek");
const child = spawn(binary, ["serve", "--config", configPath], { stdio: "inherit" });

child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error(`cannot start ${binary}: ${err.message}`);
  console.error("build it first: make build");
  process.exit(1);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}
