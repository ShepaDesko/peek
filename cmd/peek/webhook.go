package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
	"github.com/ShepaDesko/peek/internal/webhooks"
)

// peek webhook — look at the outbound notifications from the host.
//
// This is the command an operator reaches for when a receiver has been down:
// list says what is configured, test proves the path, queue says what is owed
// and why, retry sends the backlog once the receiver is back.
//
// It runs against the database directly, so it works on a node whose service
// is stopped — which is often exactly when you want it.

func runWebhook(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail("usage: peek webhook list|test|queue|retry [options]")
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("webhook "+sub, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	state := fs.String("state", "", "queue filter: pending, delivered or failed")
	endpoint := fs.String("endpoint", "", "limit to one endpoint")
	id := fs.String("id", "", "a single delivery, for retry")
	limit := fs.Int("limit", 30, "how many rows to show")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		return webhookList(cfg)
	case "test":
		name := strings.TrimSpace(strings.Join(fs.Args(), " "))
		if name == "" && *endpoint != "" {
			name = *endpoint
		}
		return webhookTest(ctx, &cfg, name)
	case "queue":
		return webhookQueue(ctx, &cfg, *state, *endpoint, *limit)
	case "retry":
		return webhookRetry(ctx, &cfg, *id, *endpoint)
	default:
		return fail("unknown subcommand %q: expected list, test, queue or retry", sub)
	}
}

func webhookList(cfg config.Config) error {
	if len(cfg.Webhooks) == 0 {
		fmt.Println("No webhook is configured.")
		fmt.Println()
		fmt.Println("Declare one in peek.toml:")
		fmt.Println()
		fmt.Println("    [[webhook]]")
		fmt.Println(`    name   = "siem"`)
		fmt.Println(`    url    = "https://hooks.example.com/peek"`)
		fmt.Println(`    secret = "a long random string"`)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tURL\tEVENTS\tATTEMPTS\tSTATE")
	for _, hook := range cfg.Webhooks {
		state := "enabled"
		if hook.Disabled {
			state = "disabled"
		}
		if hook.SkipVerify {
			state += ", TLS unverified"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			hook.Name, hook.URL, strings.Join(hook.EventList(), " "), hook.Attempts(), state)
	}
	return w.Flush()
}

func webhookTest(ctx context.Context, cfg *config.Config, name string) error {
	if name == "" {
		if len(cfg.Webhooks) != 1 {
			return fail("peek webhook test needs the endpoint name, for example: peek webhook test siem")
		}
		name = cfg.Webhooks[0].Name
	}
	st, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	sender, err := webhooks.NewDeliverer(cfg, st, quietLogger(), version)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	status, err := sender.Ping(ctx, name)
	if err != nil {
		return fail("%s refused the test delivery: %v", name, err)
	}
	fmt.Printf("%s accepted the test delivery (HTTP %d).\n", name, status)
	return nil
}

func webhookQueue(ctx context.Context, cfg *config.Config, state, endpoint string, limit int) error {
	st, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	stats, err := st.DeliveryStats(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("pending %d, delivered %d, failed %d\n", stats.Pending, stats.Delivered, stats.Failed)
	if !stats.Oldest.IsZero() {
		fmt.Printf("oldest pending: %s (%s ago)\n",
			stats.Oldest.Format(time.RFC3339), time.Since(stats.Oldest).Round(time.Second))
	}

	rows, err := st.ListDeliveries(ctx, store.DeliveryFilter{
		Endpoint: endpoint, State: state, Limit: limit,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("\nNothing in the queue.")
		return nil
	}
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tENDPOINT\tEVENT\tTRIES\tSTATE\tDETAIL")
	for _, row := range rows {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
			row.ID, row.Endpoint, row.Event, row.Attempts, deliveryState(row), deliveryDetail(row))
	}
	return w.Flush()
}

func deliveryState(row store.Delivery) string {
	switch {
	case row.Delivered != nil:
		return "delivered"
	case row.Failed != nil:
		return "failed"
	default:
		return "pending"
	}
}

func deliveryDetail(row store.Delivery) string {
	if row.LastError != "" {
		if row.LastStatus != 0 {
			return fmt.Sprintf("HTTP %d: %s", row.LastStatus, row.LastError)
		}
		return row.LastError
	}
	if row.Pending() {
		return "due " + row.NextAt.Format(time.RFC3339)
	}
	if row.LastStatus != 0 {
		return fmt.Sprintf("HTTP %d", row.LastStatus)
	}
	return ""
}

func webhookRetry(ctx context.Context, cfg *config.Config, id, endpoint string) error {
	st, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	now := time.Now()
	if id != "" {
		ok, err := st.RetryDelivery(ctx, id, now)
		if err != nil {
			return err
		}
		if !ok {
			return fail("no failed delivery with identifier %q", id)
		}
		fmt.Println("1 delivery is back in the queue.")
		return nil
	}
	n, err := st.RetryFailedDeliveries(ctx, endpoint, now)
	if err != nil {
		return err
	}
	switch n {
	case 0:
		fmt.Println("Nothing to retry.")
	case 1:
		fmt.Println("1 delivery is back in the queue.")
	default:
		fmt.Printf("%d deliveries are back in the queue.\n", n)
	}
	if n > 0 {
		fmt.Println("The running service drains it within ten seconds.")
	}
	return nil
}
