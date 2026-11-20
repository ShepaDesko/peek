package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/ShepaDesko/peek/internal/mail"
	"github.com/ShepaDesko/peek/internal/store"
)

// The messages Peek sends.
//
// They are deliberately plain: a link, what it is for, how long it lasts, and
// nothing that would open it on its own. Branded HTML templates arrive with
// the branding editor in M6; the text here is what a mail client that refuses
// HTML will always see.

func (s *Server) publicLink(path string) string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + path
}

// mailInvitation sends an invitation link.
func (s *Server) mailInvitation(ctx context.Context, to, token, inviter string) error {
	link := s.publicLink("/invitation#" + token)
	brand := s.brandName()
	from := "Un administrateur"
	if inviter != "" {
		from = inviter
	}

	text := fmt.Sprintf(`%s vous invite a rejoindre %s.

%s sert a partager des secrets par liens ephemeres, chiffres de bout en bout.

Pour creer votre compte, ouvrez ce lien :

%s

Ce lien est valable 7 jours et ne fonctionne qu'une fois.
Si vous n'attendiez pas cette invitation, ignorez ce message.
`, from, brand, brand, link)

	return s.mailer.Send(ctx, mail.Message{
		To:      []string{to},
		Subject: fmt.Sprintf("Invitation a rejoindre %s", brand),
		Text:    text,
		HTML: s.simpleHTML(fmt.Sprintf("%s vous invite a rejoindre %s.", from, brand), "Creer mon compte", link,
			"Ce lien est valable 7 jours et ne fonctionne qu'une fois."),
	})
}

// mailPasswordReset sends a reset link.
func (s *Server) mailPasswordReset(ctx context.Context, user store.User, token string) error {
	link := s.publicLink("/reset#" + token)
	brand := s.brandName()

	text := fmt.Sprintf(`Une reinitialisation de mot de passe a ete demandee pour votre compte %s.

Pour choisir un nouveau mot de passe, ouvrez ce lien :

%s

Ce lien expire dans une heure et ne fonctionne qu'une fois.
Si vous n'etes pas a l'origine de cette demande, ignorez ce message :
votre mot de passe actuel reste valable.
`, brand, link)

	return s.mailer.Send(ctx, mail.Message{
		To:      []string{user.Email},
		Subject: fmt.Sprintf("Reinitialiser votre mot de passe %s", brand),
		Text:    text,
		HTML: s.simpleHTML("Une reinitialisation de mot de passe a ete demandee.",
			"Choisir un nouveau mot de passe", link,
			"Ce lien expire dans une heure. Si vous n'etes pas a l'origine de cette demande, ignorez ce message."),
	})
}

// mailSecretLink sends a recipient the link to a secret.
//
// The passphrase is never included, even when one exists: the whole point of a
// passphrase is that it travels by another route.
func (s *Server) mailSecretLink(ctx context.Context, to, link, message string, hasPassphrase bool) error {
	brand := s.brandName()
	var b strings.Builder
	fmt.Fprintf(&b, "Un secret vous a ete partage via %s.\n\n", brand)
	if message != "" {
		fmt.Fprintf(&b, "Message de l'expediteur :\n%s\n\n", message)
	}
	fmt.Fprintf(&b, "Ouvrez ce lien pour le consulter :\n\n%s\n\n", link)
	b.WriteString("Le lien expire et ne peut etre consulte qu'un nombre limite de fois.\n")
	if hasPassphrase {
		b.WriteString("\nUne passphrase est necessaire. L'expediteur vous la transmet par un autre canal :\nelle n'est jamais envoyee par e-mail.\n")
	}

	note := "Le lien expire et ne peut etre consulte qu'un nombre limite de fois."
	if hasPassphrase {
		note += " Une passphrase est necessaire ; elle ne circule jamais par e-mail."
	}
	return s.mailer.Send(ctx, mail.Message{
		To:      []string{to},
		Subject: fmt.Sprintf("Un secret vous a ete partage via %s", brand),
		Text:    b.String(),
		HTML:    s.simpleHTML(fmt.Sprintf("Un secret vous a ete partage via %s.", brand), "Consulter le secret", link, note),
	})
}

// mailSecretViewed tells a sender their secret was read.
func (s *Server) mailSecretViewed(ctx context.Context, to, secretID string, destroyed bool) error {
	brand := s.brandName()
	state := "Il reste encore des lectures disponibles."
	if destroyed {
		state = "C'etait la derniere lecture : le secret a ete detruit."
	}
	text := fmt.Sprintf(`Votre secret %s vient d'etre consulte sur %s.

%s
`, secretID, brand, state)

	return s.mailer.Send(ctx, mail.Message{
		To:      []string{to},
		Subject: fmt.Sprintf("Votre secret a ete consulte - %s", brand),
		Text:    text,
	})
}

// simpleHTML renders the one layout these messages use.
//
// Tables and inline styles, because that is what mail clients render
// predictably; no image, no web font, nothing loaded from a server, so the
// message looks the same offline and leaks no read receipt.
func (s *Server) simpleHTML(lead, action, link, note string) string {
	primary := s.cfg.Branding.PrimaryColor
	if primary == "" {
		primary = "#4f46e5"
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="fr"><body style="margin:0;padding:24px;background:#f6f7fb;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#15182a">
<table role="presentation" cellpadding="0" cellspacing="0" style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e2e5ee;border-radius:14px">
<tr><td style="padding:28px">
<p style="margin:0 0 8px;font-size:18px;font-weight:600">%s</p>
<p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#5b6079">%s</p>
<p style="margin:0 0 20px"><a href="%s" style="display:inline-block;background:%s;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:10px;font-weight:600;font-size:14px">%s</a></p>
<p style="margin:0;font-size:12px;line-height:1.6;color:#5b6079;word-break:break-all">Si le bouton ne fonctionne pas, copiez cette adresse :<br>%s</p>
</td></tr></table>
<p style="max-width:560px;margin:16px auto 0;font-size:11px;color:#5b6079;text-align:center">%s</p>
</body></html>`, htmlEscape(lead), htmlEscape(note), htmlEscape(link), htmlEscape(primary),
		htmlEscape(action), htmlEscape(link), htmlEscape(s.brandName()))
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
