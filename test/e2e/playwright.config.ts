import { defineConfig, devices } from "@playwright/test";

/**
 * The suite drives the real binary with its embedded interface, not a dev
 * server: what CI exercises is exactly what ships.
 *
 * Build it first with `make build`, from the repository root.
 */
const PORT = Number(process.env.PEEK_E2E_PORT ?? 8099);
const BASE_URL = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["html", { open: "never" }], ["list"]] : "list",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    // The account journey runs first, on its own, because its first test is
    // the only one that can ever see a fresh instance: creating the first
    // administrator is a one-time act, and the suite shares one database.
    // Everything else depends on it rather than on filenames sorting the
    // right way, which is how that dependency used to be expressed — and how
    // it broke the moment a new spec file sorted before "accounts".
    {
      name: "accounts",
      testMatch: /accounts\.spec\.ts/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "chromium",
      dependencies: ["accounts"],
      testIgnore: /accounts\.spec\.ts/,
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: `node ./start-peek.mjs ${PORT}`,
    url: `${BASE_URL}/readyz`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
