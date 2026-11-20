import { expect, test, type Page } from "@playwright/test";

/**
 * The account journey, driven through the browser against the real binary.
 *
 * The instance starts with no account at all, so the first test here creates
 * it; the helper below then signs in on later runs instead of bootstrapping
 * twice.
 */

const ADMIN_EMAIL = "admin@acme.test";
const ADMIN_PASSWORD = "un-mot-de-passe-correct-2026";

/** Creates the first administrator, or signs in when it already exists. */
async function signInAsAdmin(page: Page): Promise<void> {
  await page.goto("/login");
  // A fresh instance redirects /login to /bootstrap on its own.
  if (page.url().endsWith("/bootstrap")) {
    await page.getByLabel("Adresse e-mail").fill(ADMIN_EMAIL);
    await page.getByLabel("Mot de passe", { exact: true }).fill(ADMIN_PASSWORD);
    await page.getByRole("button", { name: "Créer le compte" }).click();
    await expect(page.getByRole("heading", { name: "Mes secrets" })).toBeVisible();
    return;
  }
  await page.getByLabel("Adresse e-mail").fill(ADMIN_EMAIL);
  await page.getByLabel("Mot de passe", { exact: true }).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Se connecter", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Mes secrets" })).toBeVisible();
}

test("a fresh instance asks for its first account, then signs it in", async ({ page }) => {
  await page.goto("/login");
  // The sign-in form is useless with no account, so the instance says so.
  await expect(page).toHaveURL(/\/bootstrap$/);
  await expect(page.getByRole("heading", { name: "Créer le premier compte" })).toBeVisible();

  await page.getByLabel("Adresse e-mail").fill(ADMIN_EMAIL);
  await page.getByLabel("Nom affiché").fill("Admin ACME");
  await page.getByLabel("Mot de passe", { exact: true }).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Créer le compte" }).click();

  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole("heading", { name: "Mes secrets" })).toBeVisible();

  // And the first-run page is gone for good.
  await page.goto("/bootstrap");
  await expect(page).not.toHaveURL(/\/bootstrap$/);
});

test("a secret created while signed in shows up on the dashboard", async ({ page }) => {
  await signInAsAdmin(page);

  await page.goto("/");
  await page.getByLabel("Secret", { exact: true }).fill("Secret attribué à un compte");
  await page.getByRole("button", { name: "Créer le lien" }).click();
  await expect(page.getByRole("heading", { name: "Votre lien est prêt" })).toBeVisible();
  const link = await page.getByLabel("Lien à transmettre").inputValue();
  const id = new URL(link).pathname.split("/").pop()!;

  await page.goto("/dashboard");
  await expect(page.getByText(id)).toBeVisible();
  await expect(page.getByRole("cell", { name: "En attente de lecture" })).toBeVisible();

  // Burning from the dashboard needs no receipt token: the creator column is
  // what proves ownership there.
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Détruire maintenant" }).first().click();
  await expect(page.getByText("Détruit", { exact: true }).first()).toBeVisible();

  await page.goto("about:blank");
  await page.goto(link);
  await expect(page.getByRole("heading", { name: "Ce lien n'est plus valide" })).toBeVisible();
});

test("the audit trail is not readable without signing in", async ({ page, request }) => {
  const anonymous = await request.get("/api/v1/audit");
  expect(anonymous.status()).toBe(401);

  await signInAsAdmin(page);
  await page.goto("/admin");
  await page.getByRole("tab", { name: "Journal d'audit" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.getByText("admin.user_created").first()).toBeVisible();
});

test("a signed-out browser cannot reach the dashboard", async ({ page }) => {
  await signInAsAdmin(page);
  await page.getByRole("button", { name: "Se déconnecter" }).click();
  await expect(page.getByRole("link", { name: "Se connecter" })).toBeVisible();

  await page.goto("/dashboard");
  // The page offers to sign in rather than showing somebody else's secrets.
  await expect(page.getByRole("button", { name: "Se connecter" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Mes secrets" })).toBeHidden();
});

test("a wrong password says the same thing as an unknown address", async ({ page }) => {
  await signInAsAdmin(page);
  await page.getByRole("button", { name: "Se déconnecter" }).click();

  await page.goto("/login");
  await page.getByLabel("Adresse e-mail").fill(ADMIN_EMAIL);
  await page.getByLabel("Mot de passe", { exact: true }).fill("ce-nest-pas-le-bon-mot-de-passe");
  await page.getByRole("button", { name: "Se connecter", exact: true }).click();
  await expect(page.getByText("Adresse ou mot de passe incorrect.")).toBeVisible();

  await page.getByLabel("Adresse e-mail").fill("personne@acme.test");
  await page.getByRole("button", { name: "Se connecter", exact: true }).click();
  await expect(page.getByText("Adresse ou mot de passe incorrect.")).toBeVisible();
});

test("an administrator invites somebody and gets a usable link", async ({ page }) => {
  await signInAsAdmin(page);
  await page.goto("/admin");

  await page.getByLabel("Adresse e-mail").fill("invite@acme.test");
  await page.locator("#invite-role").selectOption("manager");
  await page.getByRole("button", { name: "Inviter", exact: true }).click();

  // With no SMTP configured the instance hands the link over instead.
  await expect(page.getByText(/Aucun SMTP configuré/)).toBeVisible();
  const link = await page.getByLabel("Lien d'invitation").inputValue();
  expect(link).toContain("/invitation#");

  await page.getByRole("button", { name: "Se déconnecter" }).click();
  await page.goto(link);
  await expect(page.getByRole("heading", { name: "Rejoindre l'instance" })).toBeVisible();
  await expect(page.getByText(/invite@acme.test/)).toBeVisible();

  await page.getByLabel("Choisissez un mot de passe").fill("un-autre-mot-de-passe-2026");
  await page.getByRole("button", { name: "Créer mon compte" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);

  // A manager sees administration, but not the instance tab.
  await page.goto("/admin");
  await expect(page.getByRole("tab", { name: "Utilisateurs" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Instance" })).toBeHidden();
});

test("the account page offers the second factor and lists the session", async ({ page }) => {
  await signInAsAdmin(page);
  await page.goto("/account");

  await expect(page.getByRole("heading", { name: "Mon compte" })).toBeVisible();
  await expect(page.getByText(ADMIN_EMAIL)).toBeVisible();
  await expect(page.getByText("Cette session", { exact: false })).toBeVisible();

  await page.getByRole("button", { name: "Activer" }).click();
  await expect(page.getByText("Scannez ce QR code avec votre application d'authentification.")).toBeVisible();
  // The seed is shown once, for an authenticator that cannot scan.
  const secret = await page.locator("code").first().textContent();
  expect(secret?.trim().length).toBeGreaterThan(15);
});
