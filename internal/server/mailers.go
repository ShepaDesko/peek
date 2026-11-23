package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/branding"
	"github.com/ShepaDesko/peek/internal/mail"
	"github.com/ShepaDesko/peek/internal/store"
)

// The messages Peek sends.
//
// They carry a link, what it is for, and how long it lasts — never a
// passphrase and never a key. They are branded from the instance theme, and
// every one of them also exists as plain text, because a mail client that
// refuses HTML must still be usable.

// publicLink builds an absolute link for the organisation of this request.
//
// In multi-organisation mode that is the organisation's own primary domain, so
// the address in the link, the certificate that serves it and the brand on the
// page all agree. A single-tenant instance gets public_url, unchanged.
//
// It takes a context rather than reading the configuration directly for that
// reason: a link is the one artefact that leaves the instance, and building it
// from the wrong origin sends a customer's recipient to somebody else's
// address.
func (s *Server) publicLink(ctx context.Context, path string) string {
	return strings.TrimRight(s.orgs.PublicURL(ctx, OrgOf(ctx).ID), "/") + path
}

// mailTheme resolves the brand of the organisation the request belongs to.
//
// An e-mail is the one place the brand leaves the instance, so it has to be
// the customer's and not the instance's: a link sent from acme must arrive
// looking like acme. The organisation comes from the request context, which
// means the same function works on a single-tenant instance without knowing
// it — there the context always holds the default organisation.
func (s *Server) mailTheme(ctx context.Context) branding.Resolved {
	orgID := OrgOf(ctx).ID
	var stored *store.Branding
	if saved, err := s.store.Branding(ctx, orgID); err == nil {
		stored = &saved
	}
	assets, _ := s.store.ListAssets(ctx, orgID)
	return branding.Resolve(s.cfg, stored, assets, languages)
}

// brandText returns an administrator's override for a key, or the fallback.
func brandText(theme branding.Resolved, key, fallback string) string {
	if entries, ok := theme.Texts[theme.Language]; ok {
		if value := strings.TrimSpace(entries[key]); value != "" {
			return value
		}
	}
	return fallback
}

// mailInvitation sends an invitation link.
func (s *Server) mailInvitation(ctx context.Context, to, token, inviter string) error {
	theme := s.mailTheme(ctx)
	link := s.publicLink(ctx, "/invitation#"+token)
	from := "Un administrateur"
	if inviter != "" {
		from = inviter
	}

	text := fmt.Sprintf(`%s vous invite à rejoindre %s.

%s sert à partager des secrets par liens éphémères, chiffrés de bout en bout.

Pour créer votre compte, ouvrez ce lien :

%s

Ce lien est valable 7 jours et ne fonctionne qu'une fois.
Si vous n'attendiez pas cette invitation, ignorez ce message.
%s`, from, theme.ServiceName, theme.ServiceName, link, signature(theme))

	return s.mailer.Send(ctx, mail.Message{
		To:      []string{to},
		Subject: fmt.Sprintf("Invitation à rejoindre %s", theme.ServiceName),
		Text:    text,
		HTML: s.brandedHTML(theme,
			fmt.Sprintf("%s vous invite à rejoindre %s.", from, theme.ServiceName),
			"Ce lien est valable 7 jours et ne fonctionne qu'une fois.",
			"Créer mon compte", link, ""),
	})
}

// mailPasswordReset sends a reset link.
func (s *Server) mailPasswordReset(ctx context.Context, user store.User, token string) error {
	theme := s.mailTheme(ctx)
	link := s.publicLink(ctx, "/reset#"+token)

	text := fmt.Sprintf(`Une réinitialisation de mot de passe a été demandée pour votre compte %s.

Pour choisir un nouveau mot de passe, ouvrez ce lien :

%s

Ce lien expire dans une heure et ne fonctionne qu'une fois.
Si vous n'êtes pas à l'origine de cette demande, ignorez ce message :
votre mot de passe actuel reste valable.
%s`, theme.ServiceName, link, signature(theme))

	return s.mailer.Send(ctx, mail.Message{
		To:      []string{user.Email},
		Subject: fmt.Sprintf("Réinitialiser votre mot de passe %s", theme.ServiceName),
		Text:    text,
		HTML: s.brandedHTML(theme,
			"Une réinitialisation de mot de passe a été demandée.",
			"Ce lien expire dans une heure. Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.",
			"Choisir un nouveau mot de passe", link, ""),
	})
}

// mailSecretLink sends a recipient the link to a secret.
//
// The passphrase is never included, even when one exists: the whole point of a
// passphrase is that it travels by another route.
func (s *Server) mailSecretLink(ctx context.Context, to, link, message string, hasPassphrase bool) error {
	theme := s.mailTheme(ctx)

	var b strings.Builder
	fmt.Fprintf(&b, "Un secret vous a été partagé via %s.\n\n", theme.ServiceName)
	if message != "" {
		fmt.Fprintf(&b, "Message de l'expéditeur :\n%s\n\n", message)
	}
	fmt.Fprintf(&b, "Ouvrez ce lien pour le consulter :\n\n%s\n\n", link)
	b.WriteString("Le lien expire et ne peut être consulté qu'un nombre limité de fois.\n")
	if hasPassphrase {
		b.WriteString("\nUne passphrase est nécessaire. L'expéditeur vous la transmet par un autre canal :\n" +
			"elle n'est jamais envoyée par e-mail.\n")
	}
	b.WriteString(signature(theme))

	note := "Le lien expire et ne peut être consulté qu'un nombre limité de fois."
	if hasPassphrase {
		note += " Une passphrase est nécessaire ; elle ne circule jamais par e-mail."
	}
	return s.mailer.Send(ctx, mail.Message{
		To:      []string{to},
		Subject: fmt.Sprintf("Un secret vous a été partagé via %s", theme.ServiceName),
		Text:    b.String(),
		HTML: s.brandedHTML(theme,
			fmt.Sprintf("Un secret vous a été partagé via %s.", theme.ServiceName),
			note, "Consulter le secret", link, message),
	})
}

// mailSecretViewed tells a sender their secret was read.
func (s *Server) mailSecretViewed(ctx context.Context, to, secretID string, destroyed bool) error {
	theme := s.mailTheme(ctx)
	state := "Il reste encore des lectures disponibles."
	if destroyed {
		state = "C'était la dernière lecture : le secret a été détruit."
	}
	text := fmt.Sprintf("Votre secret %s vient d'être consulté sur %s.\n\n%s\n%s",
		secretID, theme.ServiceName, state, signature(theme))

	return s.mailer.Send(ctx, mail.Message{
		To:      []string{to},
		Subject: fmt.Sprintf("Votre secret a été consulté — %s", theme.ServiceName),
		Text:    text,
		HTML:    s.brandedHTML(theme, "Votre secret vient d'être consulté.", state, "", "", ""),
	})
}

func signature(theme branding.Resolved) string {
	custom := brandText(theme, "email.signature", "")
	if custom == "" {
		return ""
	}
	return "\n--\n" + custom + "\n"
}

// brandedHTML renders the one layout these messages use.
//
// Tables and inline styles, because that is what mail clients render
// predictably. Nothing is loaded from a server — no image, no web font — so
// the message looks the same offline and carries no read receipt. The logo is
// deliberately absent for that reason: a remote image in a mail is a tracker,
// whoever sends it.
func (s *Server) brandedHTML(theme branding.Resolved, lead, note, action, link, message string) string {
	primary := theme.PrimaryColor
	if primary == "" {
		primary = "#4f46e5"
	}
	onPrimary := theme.Palette["on-primary"]
	if onPrimary == "" {
		onPrimary = "#ffffff"
	}
	radius := theme.RadiusValue
	if radius == "" {
		radius = "10px"
	}

	var body strings.Builder
	fmt.Fprintf(&body,
		`<p style="margin:0 0 8px;font-size:18px;font-weight:600">%s</p>`, htmlEscape(lead))
	if message != "" {
		fmt.Fprintf(&body,
			`<p style="margin:0 0 16px;padding:12px;border-radius:%s;background:#f6f7fb;font-size:14px;line-height:1.6;color:#15182a">%s</p>`,
			htmlEscape(radius), htmlEscape(message))
	}
	fmt.Fprintf(&body,
		`<p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#5b6079">%s</p>`, htmlEscape(note))
	if action != "" && link != "" {
		fmt.Fprintf(&body,
			`<p style="margin:0 0 20px"><a href="%s" style="display:inline-block;background:%s;color:%s;text-decoration:none;padding:12px 20px;border-radius:%s;font-weight:600;font-size:14px">%s</a></p>`+
				`<p style="margin:0;font-size:12px;line-height:1.6;color:#5b6079;word-break:break-all">Si le bouton ne fonctionne pas, copiez cette adresse :<br>%s</p>`,
			htmlEscape(link), htmlEscape(primary), htmlEscape(onPrimary), htmlEscape(radius),
			htmlEscape(action), htmlEscape(link))
	}

	footer := theme.ServiceName
	if sig := brandText(theme, "email.signature", ""); sig != "" {
		footer = sig
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="fr"><body style="margin:0;padding:24px;background:#f6f7fb;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#15182a">
<table role="presentation" cellpadding="0" cellspacing="0" style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e2e5ee;border-radius:14px">
<tr><td style="padding:28px">
%s
</td></tr></table>
<p style="max-width:560px;margin:16px auto 0;font-size:11px;color:#5b6079;text-align:center">%s</p>
</body></html>`, body.String(), htmlEscape(footer))
}

// htmlEscape is deliberately strict: everything placed in these templates
// comes from configuration or from a user, and a mail client is a renderer
// like any other.
func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// contextWithTimeout bounds a send started from a request.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

// mailRequestDeposited tells a requester that someone answered. It carries no
// link and no content: the answer is readable only with the private key in the
// requester's own receipt link, which Peek does not have.
func (s *Server) mailRequestDeposited(ctx context.Context, to, requestID string) error {
	theme := s.mailTheme(ctx)
	text := fmt.Sprintf("Quelqu'un vient de déposer un secret sur votre demande %s (%s).\n\n"+
		"Ouvrez votre lien de suivi pour le lire : lui seul contient la clé.\n%s",
		requestID, theme.ServiceName, signature(theme))

	return s.mailer.Send(ctx, mail.Message{
		To:      []string{to},
		Subject: fmt.Sprintf("Un secret a été déposé sur votre demande — %s", theme.ServiceName),
		Text:    text,
		HTML: s.brandedHTML(theme, "Un secret a été déposé sur votre demande.",
			"Ouvrez votre lien de suivi pour le lire : lui seul contient la clé.", "", "", ""),
	})
}
