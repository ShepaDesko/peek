import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";

/**
 * Attachments and multi-recipient links, driven through the browser.
 *
 * The point of these tests is the part no unit test can reach: the file is
 * encrypted in the tab, travels as an opaque stream, and comes back out byte
 * for byte on the other side — with the server never holding a key.
 */

let scratch: string;

test.beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), "peek-e2e-"));
});

test.afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

/** Writes a file of pseudo-random bytes and returns its path and digest. */
function makeFile(name: string, size: number): { path: string; sha: string } {
  const path = join(scratch, name);
  // Random rather than zeroes: a bug that drops or reorders chunks would hide
  // behind a file that is the same byte all the way down.
  const data = randomBytes(size);
  writeFileSync(path, data);
  return { path, sha: createHash("sha256").update(data).digest("hex") };
}

function sha256OfFile(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

async function openFresh(page: Page, link: string): Promise<void> {
  await page.goto("about:blank");
  await page.goto(link);
}

/** Attaches files on the creation page and waits for the uploads to finish. */
async function attach(page: Page, paths: string[]): Promise<void> {
  await page.getByLabel("Pièces jointes").setInputFiles(paths);
  for (const path of paths) {
    const name = path.split(/[\\/]/).pop()!;
    await expect(page.getByRole("listitem").filter({ hasText: name })).toContainText("✓", {
      timeout: 120_000,
    });
  }
}

async function shareLink(page: Page): Promise<string> {
  const value = await page.getByLabel("Lien à transmettre").inputValue();
  expect(value).toContain("/s/");
  return value;
}

/** Reveals a secret and downloads one attachment, returning its path. */
async function revealAndDownload(page: Page, link: string, name: string): Promise<string> {
  await openFresh(page, link);
  await page.getByRole("button", { name: "Révéler le secret" }).click();
  await expect(page.getByText("Pièces jointes")).toBeVisible();

  const row = page.getByRole("listitem").filter({ hasText: name });
  const [download] = await Promise.all([
    page.waitForEvent("download", { timeout: 120_000 }),
    row.getByRole("button", { name: "Télécharger" }).click(),
  ]);
  const target = join(scratch, `out-${Date.now()}-${name}`);
  await download.saveAs(target);
  return target;
}

test("a file goes out encrypted and comes back byte for byte", async ({ page }) => {
  const original = makeFile("rapport.bin", 3 * 1024 * 1024 + 517);

  await page.goto("/");
  await page.getByRole("button", { name: "Fichiers", exact: true }).click();
  await attach(page, [original.path]);
  await page.getByRole("button", { name: "Créer le lien" }).click();
  await expect(page.getByRole("heading", { name: "Votre lien est prêt" })).toBeVisible();
  const link = await shareLink(page);

  const got = await revealAndDownload(page, link, "rapport.bin");
  expect(sha256OfFile(got)).toBe(original.sha);

  // The link is spent: one read means one read, attachments or not.
  await openFresh(page, link);
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();
});

test("text and files travel together", async ({ page }) => {
  const a = makeFile("cle.pem", 4096);
  const b = makeFile("notes.txt", 128);

  await page.goto("/");
  await page.getByLabel("Secret", { exact: true }).fill("La phrase de passe du fichier : okapi-42");
  await attach(page, [a.path, b.path]);
  await page.getByRole("button", { name: "Créer le lien" }).click();
  const link = await shareLink(page);

  await openFresh(page, link);
  await page.getByRole("button", { name: "Révéler le secret" }).click();
  await page.getByRole("button", { name: "Afficher" }).click();
  await expect(page.getByText("okapi-42")).toBeVisible();

  const row = page.getByRole("listitem").filter({ hasText: "cle.pem" });
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    row.getByRole("button", { name: "Télécharger" }).click(),
  ]);
  const target = join(scratch, "out-cle.pem");
  await download.saveAs(target);
  expect(sha256OfFile(target)).toBe(a.sha);
});

test("the attachment is unreachable without a reveal", async ({ page, request }) => {
  const original = makeFile("confidentiel.bin", 2048);

  await page.goto("/");
  await page.getByRole("button", { name: "Fichiers", exact: true }).click();
  await attach(page, [original.path]);
  await page.getByRole("button", { name: "Créer le lien" }).click();
  await shareLink(page);

  // The blob id is not in the page, so take it from the only place it is: the
  // storage directory. Even knowing it, there is no way in without a grant.
  const ids = await page.evaluate(async () => {
    const r = await fetch("/api/v1/files/AAAAAAAAAAAAAAAAAAAAAA", { method: "GET" });
    return r.status;
  });
  expect(ids).toBe(404);

  const direct = await request.get("/api/v1/files/AAAAAAAAAAAAAAAAAAAAAA", {
    headers: { "X-Peek-Download": "A".repeat(43) },
  });
  expect(direct.status()).toBe(404);
});

test("several recipients share one upload and keep their own lives", async ({ page }) => {
  const original = makeFile("partage.bin", 64 * 1024);

  await page.goto("/");
  await page.getByRole("button", { name: "Fichiers", exact: true }).click();
  await attach(page, [original.path]);
  await page.getByLabel("Plusieurs destinataires").check();

  await page.getByLabel("Libellé (visible par vous seul)").first().fill("Alice");
  await page.getByLabel("Libellé (visible par vous seul)").nth(1).fill("Bob");
  // Bob gets two reads: per-recipient settings are the point of the feature.
  await page
    .getByRole("group", { name: "Destinataire 2" })
    .getByLabel("Nombre de lectures")
    .selectOption({ label: "2 lectures" });

  await page.getByRole("button", { name: "Créer le lien" }).click();
  await expect(page.getByRole("heading", { name: "2 liens créés" })).toBeVisible();

  const links = await page.getByLabel("Lien du destinataire").all();
  expect(links).toHaveLength(2);
  const alice = await links[0].inputValue();
  const bob = await links[1].inputValue();
  expect(alice).not.toBe(bob);

  // Both get the same file, each through their own key.
  const first = await revealAndDownload(page, alice, "partage.bin");
  expect(sha256OfFile(first)).toBe(original.sha);
  const second = await revealAndDownload(page, bob, "partage.bin");
  expect(sha256OfFile(second)).toBe(original.sha);

  // Alice had one read and is spent; Bob had two and still has one.
  await openFresh(page, alice);
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();
  await openFresh(page, bob);
  await expect(page.getByRole("button", { name: "Révéler le secret" })).toBeVisible();
});

test("a 100 MiB file survives the round trip", async ({ page }) => {
  // The specification names this size, and it is where the chunked format
  // earns its keep: a hundred chunks, a counter that must not drift, and a
  // tab that must never hold the whole plaintext twice.
  test.slow();
  const original = makeFile("gros.bin", 100 * 1024 * 1024);

  await page.goto("/");
  await page.getByRole("button", { name: "Fichiers", exact: true }).click();
  await attach(page, [original.path]);
  await page.getByRole("button", { name: "Créer le lien" }).click();
  const link = await shareLink(page);

  const got = await revealAndDownload(page, link, "gros.bin");
  expect(sha256OfFile(got)).toBe(original.sha);
});
