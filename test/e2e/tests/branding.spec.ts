import { expect, test, type Page } from "@playwright/test";

/**
 * White-labelling, driven through the page an administrator actually uses.
 *
 * The server has always accepted a per-token palette; what this checks is the
 * other half, which was missing for a while: that the customisation page lets
 * somebody set one without editing peek.toml, and that what they set reaches
 * the stylesheet every visitor loads.
 */

const ADMIN_EMAIL = "admin@acme.test";
const ADMIN_PASSWORD = "un-mot-de-passe-correct-2026";

// accent-soft is the one palette token nothing else in this suite depends on,
// so pinning it here cannot make another test fail while this one runs. The
// mechanism is the same for all eight.
const TOKEN_LABEL = "Accent, fond clair (hex)";
const PINNED = "#123456";

async function openCustomisation(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Adresse e-mail").fill(ADMIN_EMAIL);
  await page.getByLabel("Mot de passe", { exact: true }).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Se connecter", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Mes secrets" })).toBeVisible();

  await page.goto("/admin");
  await page.getByRole("tab", { name: "Personnalisation" }).click();
  await expect(page.getByRole("heading", { name: "Palette détaillée" })).toBeVisible();
}

async function brandingCSS(page: Page): Promise<string> {
  const response = await page.request.get("/branding.css");
  expect(response.status()).toBe(200);
  return response.text();
}

test("a pinned palette token reaches the stylesheet, and letting it go takes it back", async ({
  page,
}) => {
  await openCustomisation(page);

  // Empty means derived, and the field shows the derived value as its
  // placeholder so the page says what it is about to change.
  const field = page.getByLabel(TOKEN_LABEL);
  await expect(field).toHaveValue("");
  expect(await field.getAttribute("placeholder")).toMatch(/^#[0-9a-f]{6}$/i);

  await field.fill(PINNED);
  await page.getByRole("button", { name: "Enregistrer" }).click();
  await expect(page.getByText("Marque enregistrée. Elle est visible par tous.")).toBeVisible();

  expect(await brandingCSS(page), "the pinned token is not in the served stylesheet").toContain(
    `--peek-accent-soft: ${PINNED}`,
  );

  // And back: an administrator can undo it without knowing what the derived
  // value was.
  await page.reload();
  await page.getByRole("tab", { name: "Personnalisation" }).click();
  await expect(page.getByLabel(TOKEN_LABEL)).toHaveValue(PINNED);

  await page.getByRole("button", { name: /Tout laisser dériver/ }).click();
  await page.getByRole("button", { name: "Enregistrer" }).click();
  await expect(page.getByText("Marque enregistrée. Elle est visible par tous.")).toBeVisible();

  expect(await brandingCSS(page), "the token stayed pinned after being cleared").not.toContain(
    PINNED,
  );
});
