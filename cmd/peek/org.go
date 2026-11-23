package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/orgs"
	"github.com/ShepaDesko/peek/internal/store"
)

// peek org — organisations and their domains, from the host.
//
// The interface can do all of this, but the first organisation of a hosted
// instance has to be created before anybody can sign in to administer it, and
// a domain usually needs verifying while the operator is still in the shell
// that edited the zone file.

func runOrg(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail("usage: peek org list|create|update|delete|domains|domain-add|domain-verify|" +
			"domain-primary|domain-remove [options]")
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("org "+sub, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	slug := fs.String("slug", "", "organisation slug, such as acme")
	name := fs.String("name", "", "display name")
	status := fs.String("status", "", "active or suspended")
	domain := fs.String("domain", "", "domain name")
	positional, err := parseFlags(fs, rest)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}
	st, closeStore, err := openStore(ctx, &cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	svc := orgs.New(&cfg, st, quietLogger())
	// A positional argument reads better than a flag for the common cases:
	// peek org create acme, peek org domain-verify secrets.acme.com.
	first := ""
	if len(positional) > 0 {
		first = positional[0]
	}

	switch sub {
	case "list":
		return orgList(ctx, svc)
	case "create":
		return orgCreate(ctx, svc, firstSet(*slug, first), *name)
	case "update":
		return orgUpdate(ctx, svc, st, firstSet(*slug, first), *name, *status)
	case "delete":
		return orgDelete(ctx, svc, st, firstSet(*slug, first))
	case "domains":
		return orgDomains(ctx, svc, st, firstSet(*slug, first))
	case "domain-add":
		return orgDomainAdd(ctx, svc, st, *slug, firstSet(*domain, first))
	case "domain-verify":
		return orgDomainVerify(ctx, svc, firstSet(*domain, first))
	case "domain-primary":
		return orgDomainPrimary(ctx, svc, st, *slug, firstSet(*domain, first))
	case "domain-remove":
		return orgDomainRemove(ctx, svc, st, *slug, firstSet(*domain, first))
	default:
		return fail("unknown subcommand %q", sub)
	}
}

func orgList(ctx context.Context, svc *orgs.Service) error {
	list, err := svc.List(ctx)
	if err != nil {
		return err
	}
	if !svc.MultiOrg() {
		fmt.Println("This instance is single-tenant (multi_org = false).")
		fmt.Println("Its one organisation is shown below; set multi_org = true to host several.")
		fmt.Println()
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "SLUG\tNAME\tSTATUS\tUSERS\tSECRETS\tDOMAINS")
	for _, org := range list {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n",
			org.Slug, org.Name, org.Status, org.Counts.Users, org.Counts.Secrets,
			summariseDomains(org.Domains))
	}
	return w.Flush()
}

func summariseDomains(list []store.Domain) string {
	if len(list) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(list))
	for _, d := range list {
		label := d.Domain
		if !d.Verified() {
			label += " (unverified)"
		} else if d.Primary {
			label += " (primary)"
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

func orgCreate(ctx context.Context, svc *orgs.Service, slug, name string) error {
	if slug == "" {
		return fail("peek org create needs a slug: peek org create acme --name \"ACME Ltd\"")
	}
	org, err := svc.Create(ctx, slug, name)
	if err != nil {
		return err
	}
	fmt.Printf("Created %s (%s).\n", org.Slug, org.ID)
	fmt.Println()
	fmt.Printf("Next: add a domain, publish the record it prints, then verify it.\n")
	fmt.Printf("    sudo peek org domain-add secrets.%s.com --slug %s\n", org.Slug, org.Slug)
	return nil
}

func orgUpdate(ctx context.Context, svc *orgs.Service, st *store.Store, slug, name, status string) error {
	org, err := resolveOrg(ctx, st, slug)
	if err != nil {
		return err
	}
	if name == "" && status == "" {
		return fail("nothing to change: pass --name or --status")
	}
	if err := svc.Update(ctx, org.ID, name, status); err != nil {
		return err
	}
	fmt.Printf("Updated %s.\n", org.Slug)
	return nil
}

func orgDelete(ctx context.Context, svc *orgs.Service, st *store.Store, slug string) error {
	org, err := resolveOrg(ctx, st, slug)
	if err != nil {
		return err
	}
	if err := svc.Delete(ctx, org.ID); err != nil {
		return err
	}
	fmt.Printf("Deleted %s.\n", org.Slug)
	return nil
}

func orgDomains(ctx context.Context, svc *orgs.Service, st *store.Store, slug string) error {
	orgID := ""
	if slug != "" {
		org, err := resolveOrg(ctx, st, slug)
		if err != nil {
			return err
		}
		orgID = org.ID
	}
	list, err := svc.ListDomains(ctx, orgID)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("No domain is declared.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "DOMAIN\tORG\tSTATE\tLAST CHECK")
	for _, d := range list {
		state := "verified"
		if !d.Verified() {
			state = "unverified"
		}
		if d.Primary {
			state += ", primary"
		}
		last := "-"
		if d.CheckedAt != nil {
			last = d.CheckedAt.Format(time.RFC3339)
			if d.LastError != "" {
				last += " — " + d.LastError
			}
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.Domain, d.OrgID, state, last)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	printPendingRecords(list)
	return nil
}

func orgDomainAdd(ctx context.Context, svc *orgs.Service, st *store.Store, slug, domain string) error {
	if domain == "" {
		return fail("peek org domain-add needs a domain: peek org domain-add secrets.acme.com --slug acme")
	}
	org, err := resolveOrg(ctx, st, slug)
	if err != nil {
		return err
	}
	added, err := svc.AddDomain(ctx, org.ID, domain)
	if err != nil {
		return err
	}
	fmt.Printf("Declared %s for %s. It resolves to nothing until the record below exists.\n\n",
		added.Domain, org.Slug)
	printRecord(added)
	fmt.Println()
	fmt.Printf("Then: sudo peek org domain-verify %s\n", added.Domain)
	return nil
}

func orgDomainVerify(ctx context.Context, svc *orgs.Service, domain string) error {
	if domain == "" {
		return fail("peek org domain-verify needs a domain")
	}
	verified, err := svc.Verify(ctx, domain)
	if err != nil {
		if errors.Is(err, orgs.ErrUnverified) {
			fmt.Printf("Not verified: %v\n\n", err)
			printRecord(verified)
			fmt.Println()
			fmt.Println("DNS changes take time to propagate; try again in a few minutes.")
			// Exit non-zero without repeating the message: this is meant to
			// be usable in a provisioning script that waits for propagation.
			return exitError{code: 1, msg: ""}
		}
		return err
	}
	fmt.Printf("%s is verified.\n", verified.Domain)
	if !verified.Primary {
		fmt.Printf("\nTo build this organisation's links on it:\n")
		fmt.Printf("    sudo peek org domain-primary %s --slug <slug>\n", verified.Domain)
	}
	return nil
}

func orgDomainPrimary(ctx context.Context, svc *orgs.Service, st *store.Store, slug, domain string) error {
	org, err := resolveOrg(ctx, st, slug)
	if err != nil {
		return err
	}
	if err := svc.SetPrimary(ctx, org.ID, domain); err != nil {
		return err
	}
	fmt.Printf("%s is now the primary domain of %s.\n", store.NormaliseDomain(domain), org.Slug)
	return nil
}

func orgDomainRemove(ctx context.Context, svc *orgs.Service, st *store.Store, slug, domain string) error {
	org, err := resolveOrg(ctx, st, slug)
	if err != nil {
		return err
	}
	if err := svc.RemoveDomain(ctx, org.ID, domain); err != nil {
		return err
	}
	fmt.Printf("Removed %s.\n", store.NormaliseDomain(domain))
	return nil
}

// resolveOrg accepts a slug or an identifier, so an operator can paste either.
func resolveOrg(ctx context.Context, st *store.Store, slugOrID string) (store.Org, error) {
	if slugOrID == "" {
		return store.Org{}, fail("which organisation? pass --slug")
	}
	if org, err := st.OrgBySlug(ctx, slugOrID); err == nil {
		return org, nil
	}
	org, err := st.OrgByID(ctx, slugOrID)
	if err != nil {
		return store.Org{}, fail("no organisation %q on this instance", slugOrID)
	}
	return org, nil
}

func printRecord(d store.Domain) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TYPE\tNAME\tVALUE")
	_, _ = fmt.Fprintf(w, "TXT\t%s\t%s\n", orgs.RecordName(d.Domain), orgs.RecordValue(d.Token))
	_ = w.Flush()
}

func printPendingRecords(list []store.Domain) {
	var pending []store.Domain
	for _, d := range list {
		if !d.Verified() {
			pending = append(pending, d)
		}
	}
	if len(pending) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("Records still to publish:")
	for _, d := range pending {
		printRecord(d)
	}
}

func firstSet(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
