import { expect, test, type Page } from "@playwright/test";

/**
 * Secret requests, the inverted flow: the person asking is the only one who
 * can read the answer, and the person answering cannot read it back.
 *
 * What these tests check that a unit test cannot: the keys really are made in
 * the browser, the public key really travels in the link, and the tracking
 * link really is the only thing in the world that can open a deposit.
 */

const PROMPT = "Le mot de passe du compte SAP de recette, merci.";
const ANSWER = "SAP-recette / Tr0ub4dour&3-xK";

async function openFresh(page: Page, link: string): Promise<void> {
  await page.goto("about:blank");
  await page.goto(link);
}

/** Creates a request and returns both of its links. */
async function createRequest(
  page: Page,
  options: { deposits?: string } = {},
): Promise<{ deposit: string; tracking: string }> {
  await page.goto("/ask");
  await page.getByLabel("Ce que vous demandez").fill(PROMPT);
  if (options.deposits) {
    await page.getByLabel("Dépôts acceptés").selectOption({ label: options.deposits });
  }
  await page.getByRole("button", { name: "Créer la demande" }).click();
  await expect(page.getByLabel("Lien à envoyer")).toBeVisible();

  const deposit = await page.getByLabel("Lien à envoyer").inputValue();
  const tracking = await page.getByLabel("Votre lien de suivi").inputValue();
  expect(deposit).toContain("/q/");
  expect(deposit).toContain("#v1q.");
  expect(tracking).toContain("/qs/");
  expect(tracking).toContain("#v1r.");
  return { deposit, tracking };
}

async function deposit(page: Page, link: string, answer: string): Promise<void> {
  await openFresh(page, link);
  await expect(page.getByText(PROMPT)).toBeVisible();
  await page.getByLabel("Votre réponse").fill(answer);
  await page.getByRole("button", { name: "Déposer", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Secret déposé" })).toBeVisible();
}

test("ask, answer, read — and the answer is readable only from the tracking link", async ({
  page,
}) => {
  const links = await createRequest(page);
  await deposit(page, links.deposit, ANSWER);

  await openFresh(page, links.tracking);
  await expect(page.getByRole("heading", { name: "Suivi de la demande" })).toBeVisible();
  await expect(page.getByText("Dépôt 1")).toBeVisible();
  await page.getByRole("button", { name: "Lire", exact: true }).click();
  await expect(page.getByText(ANSWER)).toBeVisible();
});

test("a request is single use by default", async ({ page }) => {
  const links = await createRequest(page);
  await deposit(page, links.deposit, ANSWER);

  // The link is dead for everyone, including the person who just used it.
  await openFresh(page, links.deposit);
  await expect(page.getByRole("heading", { name: "Demande close" })).toBeVisible();
});

test("a request can accept several answers when the instance allows it", async ({ page }) => {
  const links = await createRequest(page, { deposits: "3 dépôts" });
  await deposit(page, links.deposit, "premier");
  await deposit(page, links.deposit, "deuxième");
  await deposit(page, links.deposit, "troisième");

  await openFresh(page, links.deposit);
  await expect(page.getByRole("heading", { name: "Demande close" })).toBeVisible();

  await openFresh(page, links.tracking);
  await expect(page.getByText("Dépôt 3")).toBeVisible();

  // Read them all, then check the set. Three answers deposited inside the same
  // second have no defined order — created_at is a unix second — so asserting
  // a top-down order would be asserting the database's tie-break.
  for (let i = 0; i < 3; i++) {
    await page.getByRole("button", { name: "Lire", exact: true }).first().click();
    await expect(page.getByRole("button", { name: "Lire", exact: true })).toHaveCount(2 - i);
  }
  for (const expected of ["premier", "deuxième", "troisième"]) {
    await expect(page.getByText(expected, { exact: true })).toBeVisible();
  }
});

test("the tracking link without its fragment reads nothing", async ({ page }) => {
  const links = await createRequest(page);
  await deposit(page, links.deposit, ANSWER);

  // Everything that opens the answer is in the fragment, which never reached
  // the server. Without it the page has nothing to work with.
  const stripped = links.tracking.split("#")[0];
  await openFresh(page, stripped);
  await expect(page.getByRole("heading", { name: "Lien incomplet" })).toBeVisible();
});

test("the deposit page refuses a tampered key", async ({ page }) => {
  const links = await createRequest(page);

  // The fragment is "v1q." then the request key then the public key. Flip a
  // character of the request key: its read token no longer matches the digest
  // the server holds, so the prompt is never released.
  const [path, fragment] = links.deposit.split("#");
  const body = fragment.slice(4);
  const broken = `v1q.${body[0] === "A" ? "B" : "A"}${body.slice(1)}`;
  await openFresh(page, `${path}#${broken}`);
  await expect(page.getByRole("heading", { name: "Demande close" })).toBeVisible();
});

test("closing a request leaves an answer already received readable", async ({ page }) => {
  const links = await createRequest(page, { deposits: "2 dépôts" });
  await deposit(page, links.deposit, ANSWER);

  await openFresh(page, links.tracking);
  await page.getByRole("button", { name: "Clore la demande" }).click();
  await expect(page.getByText("Demande close.")).toBeVisible();

  // No new answer can arrive...
  await openFresh(page, links.deposit);
  await expect(page.getByRole("heading", { name: "Demande close" })).toBeVisible();
});
