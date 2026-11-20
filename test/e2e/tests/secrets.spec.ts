import { expect, test, type Page } from "@playwright/test";

/**
 * End-to-end suite, driving the real binary with its embedded interface.
 *
 * Each test states a guarantee from the specification, and checks it the way a
 * user or an attacker would meet it — through the browser, not the API.
 */

const SECRET = "Compte ACME-PROD / mot de passe: Tr0ub4dour&3-xK";

/**
 * Opens a link with a real page load.
 *
 * page.goto() to the URL already shown is a same-document navigation when only
 * the fragment matches, so the application would keep its current state. A
 * recipient coming back to a link always gets a fresh load, and that is what
 * these tests must exercise.
 */
async function openFresh(page: Page, link: string): Promise<void> {
  await page.goto("about:blank");
  await page.goto(link);
}

/** Fills the creation form and returns the sender's receipt page URL. */
async function createSecret(
  page: Page,
  options: { secret?: string; passphrase?: string; views?: string; deletable?: boolean } = {},
): Promise<string> {
  await page.goto("/");
  await page.getByLabel("Secret", { exact: true }).fill(options.secret ?? SECRET);
  if (options.passphrase) {
    await page.getByLabel("Passphrase (optionnelle)").fill(options.passphrase);
  }
  if (options.views) {
    await page.getByLabel("Nombre de lectures").selectOption({ label: options.views });
  }
  if (options.deletable) {
    await page.getByLabel("Autoriser le destinataire à supprimer le secret").check();
  }
  await page.getByRole("button", { name: "Créer le lien" }).click();
  await expect(page.getByRole("heading", { name: "Votre lien est prêt" })).toBeVisible();
  return page.url();
}

/** Reads the share link out of the receipt page. */
async function shareLink(page: Page): Promise<string> {
  const value = await page.getByLabel("Lien à transmettre").inputValue();
  expect(value).toContain("/s/");
  expect(value).toContain("#v1.");
  return value;
}

test("create, reveal once, and the link is dead afterwards", async ({ page }) => {
  await createSecret(page);
  const link = await shareLink(page);

  await openFresh(page, link);
  await expect(page.getByText("Lectures restantes : 1")).toBeVisible();
  await page.getByRole("button", { name: "Révéler le secret" }).click();

  await page.getByRole("button", { name: "Afficher" }).click();
  await expect(page.getByText(SECRET)).toBeVisible();
  await expect(page.getByText(/détruit côté serveur/)).toBeVisible();

  // A second visit must be indistinguishable from a link that never existed.
  await openFresh(page, link);
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();
});

test("the key never leaves the browser", async ({ page }) => {
  const sent: string[] = [];
  page.on("request", (request) => {
    sent.push(request.url());
    const body = request.postData();
    if (body) sent.push(body);
  });

  await createSecret(page);
  const link = await shareLink(page);
  const key = link.split("#v1.")[1];
  expect(key).toBeTruthy();

  // Neither the key nor the plaintext may appear in any request.
  for (const payload of sent) {
    expect(payload).not.toContain(key);
    expect(payload).not.toContain(SECRET);
  }
});

test("a link preview bot consumes no read", async ({ page, request }) => {
  await createSecret(page);
  const link = await shareLink(page);
  const id = new URL(link).pathname.split("/").pop()!;

  // What a preview bot does: fetch, follow no script, post nothing.
  for (const ua of ["Slackbot-LinkExpanding 1.0", "Microsoft-Outlook-SafeLinks"]) {
    const response = await request.get(`/api/v1/secrets/${id}`, { headers: { "User-Agent": ua } });
    expect(response.status()).toBe(200);
    expect((await response.json()).views_remaining).toBe(1);
  }

  // The real recipient still gets it.
  await openFresh(page, link);
  await page.getByRole("button", { name: "Révéler le secret" }).click();
  await page.getByRole("button", { name: "Afficher" }).click();
  await expect(page.getByText(SECRET)).toBeVisible();
});

test("a wrong passphrase costs no read, and too many destroy the secret", async ({ page }) => {
  await createSecret(page, { passphrase: "canal-separe-2026" });
  const link = await shareLink(page);

  await openFresh(page, link);
  await page.getByLabel("Passphrase", { exact: true }).fill("mauvaise");
  await page.getByRole("button", { name: "Révéler le secret" }).click();
  await expect(page.getByText("Passphrase incorrecte, ou lien incomplet.")).toBeVisible();
  await expect(page.getByText("Tentatives restantes : 2")).toBeVisible();
  // No read was spent.
  await expect(page.getByText("Lectures restantes : 1")).toBeVisible();

  // The right passphrase still works after a failure.
  await page.getByLabel("Passphrase", { exact: true }).fill("canal-separe-2026");
  await page.getByRole("button", { name: "Révéler le secret" }).click();
  await page.getByRole("button", { name: "Afficher" }).click();
  await expect(page.getByText(SECRET)).toBeVisible();

  // A fresh secret, exhausted on purpose: the instance allows three attempts.
  await createSecret(page, { passphrase: "autre-passphrase" });
  const second = await shareLink(page);
  await openFresh(page, second);
  for (let i = 0; i < 3; i++) {
    await page.getByLabel("Passphrase", { exact: true }).fill(`faux-${i}`);
    await page.getByRole("button", { name: "Révéler le secret" }).click();
  }
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();

  // Even the correct passphrase cannot bring it back.
  await openFresh(page, second);
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();
});

test("a multi-read secret counts down and then disappears", async ({ page }) => {
  await createSecret(page, { views: "3 lectures" });
  const link = await shareLink(page);

  for (const remaining of [3, 2, 1]) {
    await openFresh(page, link);
    await expect(page.getByText(`Lectures restantes : ${remaining}`)).toBeVisible();
    await page.getByRole("button", { name: "Révéler le secret" }).click();
    await page.getByRole("button", { name: "Afficher" }).click();
    await expect(page.getByText(SECRET)).toBeVisible();
  }
  await openFresh(page, link);
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();
});

test("the sender can burn a secret before it is read", async ({ page }) => {
  const receipt = await createSecret(page);
  const link = await shareLink(page);

  await expect(page.getByText("En attente de lecture")).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Détruire maintenant" }).click();
  await expect(page.getByText("Le secret a été détruit.")).toBeVisible();

  await openFresh(page, link);
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();

  // The receipt keeps reporting what happened, from the tombstone.
  await openFresh(page, receipt);
  await expect(page.getByText("Détruit", { exact: true })).toBeVisible();
});

test("the receipt reflects a read", async ({ page }) => {
  const receipt = await createSecret(page);
  const link = await shareLink(page);

  await openFresh(page, link);
  await page.getByRole("button", { name: "Révéler le secret" }).click();
  await expect(page.getByRole("button", { name: "Afficher" })).toBeVisible();

  await openFresh(page, receipt);
  await expect(page.getByText("Consulté")).toBeVisible();
  await expect(page.getByText("1 / 1")).toBeVisible();
});

test("a truncated link is explained, not silently broken", async ({ page }) => {
  await createSecret(page);
  const link = await shareLink(page);

  await page.goto(link.split("#")[0]); // the fragment lost on the way
  await expect(page.getByRole("heading", { name: "Lien incomplet" })).toBeVisible();
});

test("the recipient can delete when the sender allowed it", async ({ page }) => {
  await createSecret(page, { views: "3 lectures", deletable: true });
  const link = await shareLink(page);

  await openFresh(page, link);
  await page.getByRole("button", { name: "Révéler le secret" }).click();
  await page.getByRole("button", { name: "Supprimer maintenant" }).click();
  await expect(page.getByText("Le secret a été supprimé.")).toBeVisible();

  await openFresh(page, link);
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();
});

test("branding and language reach the page", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("link", { name: /Coffre E2E/ })).toBeVisible();

  const primary = await page.evaluate(() =>
    getComputedStyle(document.documentElement).getPropertyValue("--peek-primary").trim(),
  );
  expect(primary).toBe("#1d4ed8");

  await page.getByLabel("Langue").selectOption("en");
  await expect(page.getByRole("heading", { name: "Share a secret" })).toBeVisible();
  await page.reload();
  // The choice is remembered.
  await expect(page.getByRole("heading", { name: "Share a secret" })).toBeVisible();
});

test("security headers are present on every page", async ({ page }) => {
  const response = await page.goto("/");
  const headers = response!.headers();

  expect(headers["referrer-policy"]).toBe("no-referrer");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["cache-control"]).toContain("no-store");
  expect(headers["x-robots-tag"]).toContain("noindex");

  const csp = headers["content-security-policy"];
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).not.toContain("'unsafe-inline'");
  // Required by the Argon2id WebAssembly module, and nothing more.
  expect(csp).toContain("'wasm-unsafe-eval'");
  expect(csp.replace("'wasm-unsafe-eval'", "")).not.toContain("unsafe-eval");
});

test("the public listener does not expose the admin surface", async ({ request }) => {
  const publicPort = Number(new URL(test.info().project.use.baseURL!).port) + 1;
  const base = `http://127.0.0.1:${publicPort}`;

  // Recipient routes answer there.
  expect((await request.get(`${base}/healthz`)).status()).toBe(200);

  // Everything else does not exist, as far as that listener is concerned.
  for (const path of ["/api/v1/audit", "/api/v1/policy", "/api/v1/instance"]) {
    const response = await request.get(base + path);
    expect(response.status(), `${path} must not be served publicly`).toBe(404);
  }
  const created = await request.post(`${base}/api/v1/secrets`, { data: { id: "x" } });
  expect(created.status()).toBe(404);
});

test("forwarded headers are ignored when no proxy is trusted", async ({ request }) => {
  const response = await request.get("/api/v1/ip", {
    headers: { "X-Forwarded-For": "1.2.3.4" },
  });
  const body = await response.json();
  expect(body.trusted_peer).toBe(false);
  expect(body.client_ip).not.toBe("1.2.3.4");
});

test("the audit trail records the journey without the secret", async ({ page, request }) => {
  await createSecret(page);
  const link = await shareLink(page);
  const id = new URL(link).pathname.split("/").pop()!;

  await openFresh(page, link);
  await page.getByRole("button", { name: "Révéler le secret" }).click();
  await expect(page.getByRole("button", { name: "Afficher" })).toBeVisible();

  const response = await request.get(`/api/v1/audit?secret_id=${id}`);
  expect(response.status()).toBe(200);
  const raw = await response.text();

  expect(raw).not.toContain(SECRET);
  expect(raw).not.toContain(link.split("#v1.")[1]);

  const events = (await response.json()).events.map((e: { event: string }) => e.event);
  expect(events).toContain("secret.created");
  expect(events).toContain("secret.page_viewed");
  expect(events).toContain("secret.revealed");
});
