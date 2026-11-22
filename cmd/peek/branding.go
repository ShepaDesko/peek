package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ShepaDesko/peek/internal/branding"
	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// peek branding export | import
//
// A brand is a file: prepare it once on a staging instance, keep it in the
// customer's configuration repository, and apply it at install time. The file
// carries the colours, the texts, the custom CSS and the images, so importing
// it on a fresh instance is the whole brand, not a starting point.

// brandFileFormat is the version of the exchange format. It is checked on
// import so that a newer file fails with a sentence rather than a surprise.
const brandFileFormat = 2

type brandFile struct {
	Format   int       `json:"format"`
	Exported time.Time `json:"exported_at"`
	Instance string    `json:"instance,omitempty"`

	ServiceName     string `json:"service_name,omitempty"`
	PrimaryColor    string `json:"primary_color,omitempty"`
	AccentColor     string `json:"accent_color,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	CornerRadius    string `json:"corner_radius,omitempty"`
	Font            string `json:"font,omitempty"`
	ButtonStyle     string `json:"button_style,omitempty"`
	HidePoweredBy   bool   `json:"hide_powered_by"`
	SupportURL      string `json:"support_url,omitempty"`
	LegalURL        string `json:"legal_url,omitempty"`
	PrivacyURL      string `json:"privacy_url,omitempty"`
	ContactEmail    string `json:"contact_email,omitempty"`

	Texts     branding.Texts `json:"texts,omitempty"`
	CustomCSS string         `json:"custom_css,omitempty"`

	// Assets are base64, so the whole brand stays one readable file.
	Assets []brandFileAsset `json:"assets,omitempty"`
}

type brandFileAsset struct {
	Kind        string `json:"kind"`
	ContentType string `json:"content_type"`
	Bytes       string `json:"bytes"`
}

func runBranding(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail("usage: peek branding export|import [--config PATH] [FILE]")
	}
	sub := args[0]

	fs := flag.NewFlagSet("branding "+sub, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	force := fs.Bool("force", false, "replace the current brand without asking")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	switch sub {
	case "export":
		return brandingExport(ctx, st, &cfg, fs.Args())
	case "import":
		return brandingImport(ctx, st, &cfg, fs.Args(), *force)
	case "show":
		return brandingShow(ctx, st, &cfg)
	default:
		return fail("unknown subcommand %q (expected export, import or show)", sub)
	}
}

func brandingExport(ctx context.Context, st *store.Store, cfg *config.Config, args []string) error {
	out := brandFile{
		Format:   brandFileFormat,
		Exported: time.Now().UTC(),
		Instance: cfg.PublicURL,
	}

	stored, err := st.Branding(ctx, store.DefaultOrgID)
	switch {
	case err == nil:
		out.ServiceName = stored.ServiceName
		out.PrimaryColor = stored.PrimaryColor
		out.AccentColor = stored.AccentColor
		out.BackgroundColor = stored.BackgroundColor
		out.CornerRadius = stored.CornerRadius
		out.Font = stored.Font
		out.ButtonStyle = stored.ButtonStyle
		out.HidePoweredBy = stored.HidePoweredBy
		out.SupportURL = stored.SupportURL
		out.LegalURL = stored.LegalURL
		out.PrivacyURL = stored.PrivacyURL
		out.ContactEmail = stored.ContactEmail
		out.Texts = branding.ParseTexts(stored.Texts, []string{"fr", "en"})
		out.CustomCSS = stored.CustomCSS
	case errors.Is(err, store.ErrNotFound):
		// Nothing saved yet: export what peek.toml would serve, so the file is
		// still a usable starting point.
		out.ServiceName = cfg.Branding.ServiceName
		out.PrimaryColor = cfg.Branding.PrimaryColor
		out.AccentColor = cfg.Branding.AccentColor
		out.HidePoweredBy = cfg.Branding.HidePoweredBy
		out.SupportURL = cfg.Branding.SupportURL
		out.LegalURL = cfg.Branding.LegalURL
		out.PrivacyURL = cfg.Branding.PrivacyURL
	default:
		return err
	}

	metadata, err := st.ListAssets(ctx, store.DefaultOrgID)
	if err != nil {
		return err
	}
	for _, meta := range metadata {
		asset, err := st.Asset(ctx, store.DefaultOrgID, meta.Kind)
		if err != nil {
			return err
		}
		out.Assets = append(out.Assets, brandFileAsset{
			Kind:        asset.Kind,
			ContentType: asset.ContentType,
			Bytes:       base64.StdEncoding.EncodeToString(asset.Bytes),
		})
	}

	buf, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')

	if len(args) == 1 {
		if err := os.WriteFile(args[0], buf, 0o644); err != nil { //nolint:gosec // a brand file is not a secret
			return err
		}
		fmt.Printf("brand exported to %s (%d asset(s))\n", args[0], len(out.Assets))
		return nil
	}
	_, err = os.Stdout.Write(buf)
	return err
}

func brandingImport(ctx context.Context, st *store.Store, cfg *config.Config, args []string, force bool) error {
	if len(args) != 1 {
		return fail("usage: peek branding import FILE")
	}
	buf, err := os.ReadFile(args[0]) //nolint:gosec // the operator names the brand file
	if err != nil {
		return err
	}
	var in brandFile
	if err := json.Unmarshal(buf, &in); err != nil {
		return fmt.Errorf("%s is not a valid brand file: %w", args[0], err)
	}
	if in.Format > brandFileFormat {
		return fail("this brand file is format %d; this version of Peek reads up to %d", in.Format, brandFileFormat)
	}

	// Everything is checked here, before anything is written: a half-imported
	// brand is worse than a refused one.
	css, err := branding.CheckCSS(in.CustomCSS)
	if err != nil {
		return fmt.Errorf("custom CSS refused: %w", err)
	}
	texts, err := branding.MarshalTexts(in.Texts, []string{"fr", "en"})
	if err != nil {
		return err
	}
	type pending struct {
		kind        string
		contentType string
		data        []byte
	}
	var assets []pending
	for _, asset := range in.Assets {
		if !store.ValidAssetKind(asset.Kind) {
			return fail("unknown image kind %q in the brand file", asset.Kind)
		}
		data, err := base64.StdEncoding.DecodeString(asset.Bytes)
		if err != nil {
			return fmt.Errorf("image %s is not readable: %w", asset.Kind, err)
		}
		contentType, err := branding.ValidateAsset(asset.Kind, data)
		if err != nil {
			return fmt.Errorf("image %s refused: %w", asset.Kind, err)
		}
		assets = append(assets, pending{kind: asset.Kind, contentType: contentType, data: data})
	}

	if _, err := st.Branding(ctx, store.DefaultOrgID); err == nil && !force {
		fmt.Printf("This instance already has a saved brand; importing replaces it.\n")
		fmt.Print("Continue? [y/N]: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			return errors.New("cancelled")
		}
	}

	saved, err := st.SaveBranding(ctx, store.Branding{
		OrgID:           store.DefaultOrgID,
		ServiceName:     in.ServiceName,
		PrimaryColor:    in.PrimaryColor,
		AccentColor:     in.AccentColor,
		BackgroundColor: in.BackgroundColor,
		CornerRadius:    in.CornerRadius,
		Font:            in.Font,
		ButtonStyle:     in.ButtonStyle,
		HidePoweredBy:   in.HidePoweredBy,
		SupportURL:      in.SupportURL,
		LegalURL:        in.LegalURL,
		PrivacyURL:      in.PrivacyURL,
		ContactEmail:    in.ContactEmail,
		Texts:           texts,
		CustomCSS:       css,
		UpdatedBy:       "cli",
	})
	if err != nil {
		return err
	}
	for _, asset := range assets {
		if err := st.SaveAsset(ctx, store.BrandingAsset{
			OrgID:       store.DefaultOrgID,
			Kind:        asset.kind,
			ContentType: asset.contentType,
			Bytes:       asset.data,
			ETag:        branding.AssetETag(asset.data),
		}); err != nil {
			return err
		}
	}
	if err := st.Append(ctx, store.AuditEvent{
		OrgID: store.DefaultOrgID, Event: store.EventBrandingChanged,
		Detail: map[string]string{"via": "cli", "version": fmt.Sprint(saved.Version)},
	}); err != nil {
		return err
	}

	resolved := branding.Resolve(cfg, &saved, nil, []string{"fr", "en"})
	fmt.Printf("brand imported: %s (%d asset(s))\n", resolved.ServiceName, len(assets))
	for _, warning := range resolved.Warnings {
		fmt.Printf("warning: %s\n", warning)
	}
	fmt.Println("it is live immediately; no restart is needed.")
	return nil
}

func brandingShow(ctx context.Context, st *store.Store, cfg *config.Config) error {
	var stored *store.Branding
	if saved, err := st.Branding(ctx, store.DefaultOrgID); err == nil {
		stored = &saved
	}
	assets, err := st.ListAssets(ctx, store.DefaultOrgID)
	if err != nil {
		return err
	}
	resolved := branding.Resolve(cfg, stored, assets, []string{"fr", "en"})

	fmt.Printf("service name   %s\n", resolved.ServiceName)
	fmt.Printf("primary        %s\n", resolved.PrimaryColor)
	fmt.Printf("accent         %s\n", resolved.AccentColor)
	fmt.Printf("font           %s\n", resolved.Font)
	fmt.Printf("corners        %s (%s)\n", resolved.Radius, resolved.RadiusValue)
	fmt.Printf("buttons        %s\n", resolved.ButtonStyle)
	fmt.Printf("powered by     %v\n", !resolved.HidePoweredBy)
	fmt.Printf("source         %s\n", source(stored))
	if len(assets) > 0 {
		fmt.Printf("images         ")
		for i, a := range assets {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("%s (%s, %d B)", a.Kind, a.ContentType, a.SizeBytes)
		}
		fmt.Println()
	}
	for _, warning := range resolved.Warnings {
		fmt.Printf("warning: %s\n", warning)
	}
	return nil
}

func source(stored *store.Branding) string {
	if stored == nil {
		return "peek.toml (nothing saved in the database)"
	}
	return fmt.Sprintf("database, version %d, updated %s",
		stored.Version, stored.UpdatedAt.Local().Format("2006-01-02 15:04"))
}
