/**
 * Minimal i18n. No library: the dictionary is two flat objects, which keeps
 * the recipient bundle small and the translation workflow obvious.
 *
 * The chosen language is remembered in localStorage; the default comes from
 * the instance branding, so an administrator decides what a first-time
 * visitor sees.
 */

export type Lang = "fr" | "en";

export const LANGS: Lang[] = ["fr", "en"];

const fr = {
  "app.tagline": "Partage de secrets à lien éphémère, chiffré de bout en bout.",
  "app.poweredBy": "Propulsé par Peek",
  "app.theme.light": "Thème clair",
  "app.theme.dark": "Thème sombre",
  "app.language": "Langue",
  "app.loading": "Chargement…",
  "app.support": "Support",
  "app.legal": "Mentions légales",
  "app.privacy": "Confidentialité",

  "create.title": "Partager un secret",
  "create.subtitle":
    "Le contenu est chiffré dans votre navigateur. Le serveur ne voit jamais la clé.",
  "create.kind.text": "Texte ou mot de passe",
  "create.kind.url": "Lien",
  "create.secret": "Secret",
  "create.secret.placeholder": "Collez le mot de passe, la clé ou la note à partager…",
  "create.url.placeholder": "https://…",
  "create.message": "Message pour le destinataire (optionnel)",
  "create.message.placeholder": "Voici l'accès au compte de recette.",
  "create.generate": "Générer un mot de passe",
  "create.generate.length": "Longueur",
  "create.entropy": "Entropie estimée",
  "create.expiry": "Expiration",
  "create.views": "Nombre de lectures",
  "create.views.one": "1 lecture (usage unique)",
  "create.views.many": "{n} lectures",
  "create.passphrase": "Passphrase (optionnelle)",
  "create.passphrase.hint":
    "À transmettre par un autre canal : SMS, appel, messagerie. Elle n'est jamais envoyée au serveur.",
  "create.passphrase.required": "Cette instance exige une passphrase.",
  "create.retrieval": "Étape « cliquer pour révéler »",
  "create.retrieval.hint":
    "Recommandé : les robots d'aperçu (Teams, Slack, antivirus mail) ne consomment alors aucune lecture.",
  "create.deletable": "Autoriser le destinataire à supprimer le secret",
  "create.submit": "Créer le lien",
  "create.submitting": "Chiffrement…",
  "create.error": "Création impossible",
  "create.disabled.title": "Création désactivée",
  "create.empty": "Saisissez un secret à partager.",

  "receipt.title": "Votre lien est prêt",
  "receipt.subtitle": "Copiez-le maintenant : cette page est le seul endroit où il apparaît.",
  "receipt.link": "Lien à transmettre",
  "receipt.copy": "Copier le lien",
  "receipt.copied": "Copié",
  "receipt.qr": "QR code",
  "receipt.status": "Statut",
  "receipt.status.active": "En attente de lecture",
  "receipt.status.viewed": "Consulté",
  "receipt.status.expired": "Expiré",
  "receipt.status.burned": "Détruit",
  "receipt.status.deleted": "Supprimé par le destinataire",
  "receipt.status.locked": "Détruit (trop de tentatives)",
  "receipt.views": "Lectures",
  "receipt.expires": "Expire",
  "receipt.created": "Créé",
  "receipt.burn": "Détruire maintenant",
  "receipt.burn.confirm": "Détruire ce secret immédiatement ? Cette action est irréversible.",
  "receipt.burned": "Le secret a été détruit.",
  "receipt.new": "Partager un autre secret",
  "receipt.keepLink":
    "Conservez cette page pour suivre le statut : son adresse contient le jeton de suivi.",
  "receipt.passphraseReminder": "N'oubliez pas de transmettre la passphrase séparément du lien.",

  "reveal.title": "Un secret vous a été partagé",
  "reveal.warning": "Ce secret ne s'affiche qu'un nombre limité de fois.",
  "reveal.remaining": "Lectures restantes : {n}",
  "reveal.expires": "Expire {when}",
  "reveal.button": "Révéler le secret",
  "reveal.revealing": "Déchiffrement…",
  "reveal.passphrase": "Passphrase",
  "reveal.passphrase.hint": "Demandez-la à l'expéditeur, elle ne circule pas avec le lien.",
  "reveal.attempts": "Tentatives restantes : {n}",
  "reveal.badToken": "Passphrase incorrecte, ou lien incomplet.",
  "reveal.locked": "Trop de tentatives : le secret a été détruit.",
  "reveal.gone.title": "Ce lien n'est plus valide",
  "reveal.gone.body":
    "Il a peut-être déjà été consulté, il a expiré, ou il a été détruit. Demandez-en un nouveau à l'expéditeur.",
  "reveal.noKey.title": "Lien incomplet",
  "reveal.noKey.body":
    "La clé de déchiffrement se trouve après le # dans l'adresse. Copiez le lien en entier, sans le tronquer.",
  "reveal.copy": "Copier",
  "reveal.copied": "Copié",
  "reveal.show": "Afficher",
  "reveal.hide": "Masquer",
  "reveal.open": "Ouvrir le lien",
  "reveal.delete": "Supprimer maintenant",
  "reveal.deleted": "Le secret a été supprimé.",
  "reveal.consumed":
    "Ce secret vient d'être détruit côté serveur : fermez cette page une fois le contenu copié.",
  "reveal.lastView": "Il ne reste aucune lecture après celle-ci.",
  "reveal.message": "Message de l'expéditeur",

  "expiry.5m": "5 minutes",
  "expiry.1h": "1 heure",
  "expiry.24h": "24 heures",
  "expiry.7d": "7 jours",
  "expiry.30d": "30 jours",

  "error.network": "Le serveur est injoignable.",
  "error.generic": "Une erreur est survenue.",
  "error.rate": "Trop de tentatives. Patientez un instant.",
} as const;

type Key = keyof typeof fr;

const en: Record<Key, string> = {
  "app.tagline": "Ephemeral secret sharing, encrypted end to end.",
  "app.poweredBy": "Powered by Peek",
  "app.theme.light": "Light theme",
  "app.theme.dark": "Dark theme",
  "app.language": "Language",
  "app.loading": "Loading…",
  "app.support": "Support",
  "app.legal": "Legal",
  "app.privacy": "Privacy",

  "create.title": "Share a secret",
  "create.subtitle": "The content is encrypted in your browser. The server never sees the key.",
  "create.kind.text": "Text or password",
  "create.kind.url": "Link",
  "create.secret": "Secret",
  "create.secret.placeholder": "Paste the password, key or note to share…",
  "create.url.placeholder": "https://…",
  "create.message": "Message for the recipient (optional)",
  "create.message.placeholder": "Here is the access to the staging account.",
  "create.generate": "Generate a password",
  "create.generate.length": "Length",
  "create.entropy": "Estimated entropy",
  "create.expiry": "Expiry",
  "create.views": "Number of reads",
  "create.views.one": "1 read (one-time)",
  "create.views.many": "{n} reads",
  "create.passphrase": "Passphrase (optional)",
  "create.passphrase.hint":
    "Send it through another channel: SMS, a call, chat. It never reaches the server.",
  "create.passphrase.required": "This instance requires a passphrase.",
  "create.retrieval": "Click-to-reveal step",
  "create.retrieval.hint":
    "Recommended: link preview bots (Teams, Slack, mail antivirus) then consume no read.",
  "create.deletable": "Let the recipient delete the secret",
  "create.submit": "Create the link",
  "create.submitting": "Encrypting…",
  "create.error": "Could not create the secret",
  "create.disabled.title": "Creation disabled",
  "create.empty": "Enter a secret to share.",

  "receipt.title": "Your link is ready",
  "receipt.subtitle": "Copy it now: this page is the only place it appears.",
  "receipt.link": "Link to share",
  "receipt.copy": "Copy link",
  "receipt.copied": "Copied",
  "receipt.qr": "QR code",
  "receipt.status": "Status",
  "receipt.status.active": "Waiting to be read",
  "receipt.status.viewed": "Read",
  "receipt.status.expired": "Expired",
  "receipt.status.burned": "Destroyed",
  "receipt.status.deleted": "Deleted by the recipient",
  "receipt.status.locked": "Destroyed (too many attempts)",
  "receipt.views": "Reads",
  "receipt.expires": "Expires",
  "receipt.created": "Created",
  "receipt.burn": "Destroy now",
  "receipt.burn.confirm": "Destroy this secret right away? This cannot be undone.",
  "receipt.burned": "The secret has been destroyed.",
  "receipt.new": "Share another secret",
  "receipt.keepLink":
    "Keep this page to follow the status: its address carries the tracking token.",
  "receipt.passphraseReminder": "Remember to send the passphrase separately from the link.",

  "reveal.title": "A secret has been shared with you",
  "reveal.warning": "This secret can only be displayed a limited number of times.",
  "reveal.remaining": "Reads left: {n}",
  "reveal.expires": "Expires {when}",
  "reveal.button": "Reveal the secret",
  "reveal.revealing": "Decrypting…",
  "reveal.passphrase": "Passphrase",
  "reveal.passphrase.hint": "Ask the sender for it; it does not travel with the link.",
  "reveal.attempts": "Attempts left: {n}",
  "reveal.badToken": "Wrong passphrase, or the link is incomplete.",
  "reveal.locked": "Too many attempts: the secret has been destroyed.",
  "reveal.gone.title": "This link is no longer valid",
  "reveal.gone.body":
    "It may already have been read, expired, or been destroyed. Ask the sender for a new one.",
  "reveal.noKey.title": "Incomplete link",
  "reveal.noKey.body":
    "The decryption key sits after the # in the address. Copy the whole link without truncating it.",
  "reveal.copy": "Copy",
  "reveal.copied": "Copied",
  "reveal.show": "Show",
  "reveal.hide": "Hide",
  "reveal.open": "Open the link",
  "reveal.delete": "Delete now",
  "reveal.deleted": "The secret has been deleted.",
  "reveal.consumed":
    "This secret has just been destroyed on the server: close this page once you have copied it.",
  "reveal.lastView": "No read remains after this one.",
  "reveal.message": "Message from the sender",

  "expiry.5m": "5 minutes",
  "expiry.1h": "1 hour",
  "expiry.24h": "24 hours",
  "expiry.7d": "7 days",
  "expiry.30d": "30 days",

  "error.network": "The server cannot be reached.",
  "error.generic": "Something went wrong.",
  "error.rate": "Too many attempts. Please wait a moment.",
};

const dictionaries: Record<Lang, Record<Key, string>> = { fr, en };

const STORAGE_KEY = "peek.lang";

export function storedLang(): Lang | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === "fr" || v === "en" ? v : null;
  } catch {
    return null;
  }
}

export function storeLang(lang: Lang): void {
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Private browsing: remembering the choice is a convenience, not a feature.
  }
}

export function browserLang(): Lang | null {
  const nav = typeof navigator === "undefined" ? "" : navigator.language.toLowerCase();
  if (nav.startsWith("fr")) return "fr";
  if (nav.startsWith("en")) return "en";
  return null;
}

export type Translate = (key: Key, vars?: Record<string, string | number>) => string;

export function translator(lang: Lang): Translate {
  const dict = dictionaries[lang] ?? fr;
  return (key, vars) => {
    let text: string = dict[key] ?? fr[key] ?? key;
    if (vars) {
      for (const [name, value] of Object.entries(vars)) {
        text = text.replaceAll(`{${name}}`, String(value));
      }
    }
    return text;
  };
}

export type { Key as TranslationKey };
