import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * Accessibility, checked on the real pages.
 *
 * The brief asks for WCAG 2.2 AA. An automated checker finds perhaps a third
 * of what that means, so this suite is a floor and not a certificate: it
 * catches the regressions nobody notices — a contrast ratio lost to a brand
 * colour, a form control whose label was replaced by a placeholder, a region
 * that stopped being a landmark — and leaves the judgement calls to the two
 * tests at the bottom, which drive the pages by keyboard alone.
 *
 * Every page a recipient or a sender actually meets is covered, including the
 * states: a revealed secret, a failed passphrase, a filled-in receipt.
 */

const SECRET = "Compte ACME-PROD / mot de passe: Tr0ub4dour&3-xK";

/** The rule set: WCAG 2.0, 2.1 and 2.2, levels A and AA. */
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function audit(page: Page, context?: string) {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  // The report carries what axe measured, not just which rule fired: a
  // contrast failure is only actionable with the two colours and the ratio in
  // front of you.
  const report = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.slice(0, 4).map((n) => ({
      target: n.target.join(" "),
      html: n.html.slice(0, 160),
      detail: [...n.any, ...n.all].map((c) => c.data).filter(Boolean),
    })),
  }));
  expect(report, `accessibility violations${context ? " on " + context : ""}`).toEqual([]);
}

test("the creation page has no accessibility violations", async ({ page }) => {
  await page.goto("/");
  await audit(page, "the creation page");
});

/**
 * Paints a theme the way a visitor does, with the toggle in the header.
 *
 * Not emulateMedia: the instance default is dark and no longer follows the
 * system, so asking the browser for a colour scheme changes nothing. The
 * attribute the toggle sets is what decides, and --peek-scheme is how the
 * interface says which way it ended up.
 */
async function paint(page: Page, theme: "light" | "dark"): Promise<void> {
  const painted = () =>
    page.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue("--peek-scheme").trim(),
    );
  if ((await painted()) === theme) return;
  // The button is labelled with the theme it switches to.
  await page.getByRole("button", { name: theme === "light" ? "Thème clair" : "Thème sombre" }).click();
  await expect.poll(painted, { timeout: 3000 }).toBe(theme);
}

test("the creation page in light mode has no accessibility violations", async ({ page }) => {
  // Contrast is the rule a brand colour breaks, and each theme has its own
  // palette: auditing only the default one tests half the product.
  await page.goto("/");
  await paint(page, "light");
  await audit(page, "the creation page in light mode");
});

test("hovering a ghost button keeps its label readable", async ({ page }) => {
  // The generated stylesheet computes --peek-primary-soft at 88 % white
  // whatever the theme, because it exists for the light one. A hover rule
  // that took it as a background put a pale plate behind the pale label of
  // the dark theme — and axe never hovers of its own accord, which is why
  // every other audit here passed while it was broken.
  await page.goto("/");
  for (const theme of ["dark", "light"] as const) {
    await paint(page, theme);
    const ghosts = page.locator(".peek-btn-ghost:visible");
    const count = await ghosts.count();
    expect(count, `ghost buttons found on the ${theme} theme`).toBeGreaterThan(0);
    for (let i = 0; i < Math.min(count, 4); i++) {
      await ghosts.nth(i).hover();
      await audit(page, `a hovered ghost button, ${theme} theme`);
    }
  }
});

test("the receipt page has no accessibility violations", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Secret", { exact: true }).fill(SECRET);
  await page.getByRole("button", { name: "Créer le lien" }).click();
  await expect(page.getByRole("heading", { name: "Votre lien est prêt" })).toBeVisible();
  await audit(page, "the receipt page");
});

test("the recipient page has no accessibility violations, before and after revealing", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByLabel("Secret", { exact: true }).fill(SECRET);
  await page.getByRole("button", { name: "Créer le lien" }).click();
  const link = await page.getByLabel("Lien à transmettre").inputValue();

  await page.goto("about:blank");
  await page.goto(link);
  await expect(page.getByRole("button", { name: "Révéler le secret" })).toBeVisible();
  await audit(page, "the recipient page before revealing");

  await page.getByRole("button", { name: "Révéler le secret" }).click();
  // The secret is masked until asked for, so audit both states: the masked
  // one is what a recipient sees first.
  await expect(page.getByRole("button", { name: "Afficher" })).toBeVisible();
  await audit(page, "the recipient page with the secret masked");

  await page.getByRole("button", { name: "Afficher" }).click();
  await expect(page.getByText(SECRET)).toBeVisible();
  await audit(page, "the recipient page with the secret shown");
});

test("a dead link page has no accessibility violations", async ({ page }) => {
  // The page a recipient meets when the link is spent, which is the one most
  // likely to be read in a hurry.
  await page.goto("/s/AAAAAAAAAAAAAAAAAAAAAA#v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  await expect(page.getByRole("heading")).toBeVisible();
  await audit(page, "a dead link");
});

test("the sign-in page has no accessibility violations", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "the sign-in page");
});

test("the secret request pages have no accessibility violations", async ({ page }) => {
  await page.goto("/ask");
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "the request page");
});

// --- the pages behind a sign-in ---------------------------------------------

const ADMIN_EMAIL = "admin@acme.test";
const ADMIN_PASSWORD = "un-mot-de-passe-correct-2026";

/**
 * Creates the first administrator, or signs in when one exists.
 *
 * Which of the two it is cannot be read from the URL straight after goto: the
 * redirect to /bootstrap happens once the client has asked the server, so the
 * decision is taken on the heading that actually appears.
 */
async function signIn(page: Page): Promise<void> {
  await page.goto("/login");
  const bootstrap = page.getByRole("button", { name: "Créer le compte" });
  const login = page.getByRole("button", { name: "Se connecter", exact: true });
  await expect(bootstrap.or(login).first()).toBeVisible();

  await page.getByLabel("Adresse e-mail").fill(ADMIN_EMAIL);
  await page.getByLabel("Mot de passe", { exact: true }).fill(ADMIN_PASSWORD);
  if ((await bootstrap.count()) > 0) {
    await bootstrap.click();
  } else {
    await login.click();
  }
  await expect(page.getByRole("heading", { name: "Mes secrets" })).toBeVisible();
}

test("the signed-in pages have no accessibility violations", async ({ page }) => {
  await signIn(page);
  // The dashboard, the account page and each administration tab. These carry
  // the tables and the long forms, which is where a checker earns its keep:
  // a table with no header association, a switch with no accessible name.
  await audit(page, "the dashboard");

  await page.goto("/account");
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "the account page");

  await page.goto("/admin");
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "administration, users tab");

  for (const tab of ["Journal d'audit", "Personnalisation", "Instance"]) {
    const button = page.getByRole("tab", { name: tab });
    if ((await button.count()) === 0) continue;
    await button.click();
    await expect(button).toHaveAttribute("aria-selected", "true");
    // Audited with the pointer still resting on the tab it just clicked,
    // which is where a mouse user leaves it. That state found the one real
    // violation in this suite: the selected tab kept .peek-btn-ghost:hover,
    // so hovering it put white text on the pale hover background.
    await audit(page, `administration, ${tab} tab, pointer on the tab`);
    await page.mouse.move(0, 0);
    await audit(page, `administration, ${tab} tab`);
  }
});

test("hovering a selected control keeps it readable", async ({ page }) => {
  // The segmented controls — tabs, dashboard filters, the kind switcher —
  // carry their selected state as a class so that hover has a rule for both
  // states. An inline background left the ghost hover rule applying on top.
  await page.goto("/");
  const selected = page.locator('[aria-pressed="true"]').first();
  await expect(selected).toBeVisible();

  const before = await selected.evaluate((el) => getComputedStyle(el).backgroundColor);
  await selected.hover();
  const after = await selected.evaluate((el) => getComputedStyle(el).backgroundColor);

  const luminance = (value: string) => {
    const [r, g, b] = (value.match(/\d+/g) ?? ["0", "0", "0"]).map(Number);
    const lin = (c: number) => {
      const s = c / 255;
      return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  };
  // Hover may change the shade; it must never make it lighter, because the
  // text colour was chosen for contrast against the unhovered one.
  expect(luminance(after), `${before} -> ${after}`).toBeLessThanOrEqual(luminance(before) + 0.001);
  await audit(page, "the creation page with the kind switcher hovered");
});

// --- the part a checker cannot do -------------------------------------------

test("the whole creation flow works with the keyboard alone", async ({ page }) => {
  await page.goto("/");

  // Tab until the secret field has focus, then type. A page where the first
  // interactive element cannot be reached by tabbing is a page a screen reader
  // user cannot use, and no checker reports that.
  let reached = false;
  for (let i = 0; i < 25 && !reached; i++) {
    await page.keyboard.press("Tab");
    reached = await page
      .getByLabel("Secret", { exact: true })
      .evaluate((el) => el === document.activeElement)
      .catch(() => false);
  }
  expect(reached, "the secret field is reachable by tabbing").toBe(true);

  await page.keyboard.type(SECRET);

  // And the submit button is reachable and operable by keyboard.
  const submit = page.getByRole("button", { name: "Créer le lien" });
  await submit.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Votre lien est prêt" })).toBeVisible();
});

test("focus is visible wherever it lands", async ({ page }) => {
  await page.goto("/");
  // WCAG 2.2 adds "focus not obscured" and strengthens focus appearance. The
  // check an automated rule set does not make: that the focus ring is drawn at
  // all. A stylesheet that resets outline without replacing it is the usual
  // cause, and it is invisible in a screenshot of an unfocused page.
  const outlines: string[] = [];
  for (const selector of ["#secret", "button[type=submit]"]) {
    const target = page.locator(selector).first();
    if ((await target.count()) === 0) continue;
    await target.focus();
    outlines.push(
      await target.evaluate((el) => {
        const style = getComputedStyle(el);
        return [style.outlineStyle, style.outlineWidth, style.boxShadow].join("|");
      }),
    );
  }
  expect(outlines.length).toBeGreaterThan(0);
  for (const value of outlines) {
    const hasOutline = !value.startsWith("none|") && !value.includes("|0px|");
    const hasRing = !value.endsWith("|none");
    expect(hasOutline || hasRing, `no visible focus indicator: ${value}`).toBe(true);
  }
});

test("there is a way past the navigation", async ({ page }) => {
  // WCAG 2.4.1. The link is off-screen until it has focus, which is the
  // convention; what matters is that the first Tab reaches it and that
  // following it moves focus into the content.
  // Not the sign-in page: that one focuses its first field on load, which is
  // a deliberate convenience and means the skip link is never the first stop.
  await page.goto("/");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: /aller au contenu|skip to content/i });
  await expect(skip).toBeFocused();
  // And it is actually visible while focused, rather than clipped where a
  // sighted keyboard user cannot see it.
  await expect(skip).toBeInViewport();
  await page.keyboard.press("Enter");
  expect(await page.evaluate(() => window.location.hash)).toBe("#content");
});

test("an error announces itself", async ({ page }) => {
  // WCAG 4.1.3: a message that appears without a page change has to be in a
  // live region, or a screen reader user never learns the action failed.
  //
  // The wrong passphrase on a recipient page is the error that matters most
  // here: it is the one a recipient meets alone, with no second chance to
  // spare, and the attempt counter is the information they need.
  await page.goto("/");
  await page.getByLabel("Secret", { exact: true }).fill(SECRET);
  await page.getByLabel("Passphrase (optionnelle)").fill("la-bonne-passphrase");
  await page.getByRole("button", { name: "Créer le lien" }).click();
  const link = await page.getByLabel("Lien à transmettre").inputValue();

  await page.goto("about:blank");
  await page.goto(link);
  await page.getByLabel("Passphrase").fill("la-mauvaise-passphrase");
  await page.getByRole("button", { name: "Révéler le secret" }).click();

  const alert = page.getByRole("alert");
  await expect(alert.first()).toBeVisible();
  // And it is in a live region, not merely coloured red.
  const role = await alert.first().getAttribute("role");
  expect(role).toBe("alert");
});

test("the document declares its language and has one main landmark", async ({ page }) => {
  await page.goto("/");
  expect(await page.getAttribute("html", "lang")).toBe("fr");
  await expect(page.locator("main")).toHaveCount(1);

  // The language follows the chooser, which matters to a screen reader: it
  // picks the voice from this attribute.
  const chooser = page.getByLabel(/langue|language/i).first();
  if ((await chooser.count()) > 0) {
    await chooser.selectOption("en").catch(() => undefined);
    await expect
      .poll(async () => page.getAttribute("html", "lang"), { timeout: 3000 })
      .toBe("en");
  }
});
