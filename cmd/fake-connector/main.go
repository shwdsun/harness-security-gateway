// Command fake-connector exercises the real Connector HTTP/UDS boundary
// without a platform SDK or credential. It is a development fixture, not a
// generic messaging gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/secureid"
)

const (
	defaultActor        = "user/demo"
	defaultConversation = "dm/demo"
	claimInterval       = 200 * time.Millisecond
	requestTimeout      = 5 * time.Second
)

type options struct {
	socket       string
	actor        string
	conversation string
	eventID      string
	messageRef   string
	text         string
	wait         time.Duration
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fake-connector: %v\n", err)
		os.Exit(1)
	}
}

func run(parent context.Context, arguments []string, stdin io.Reader, stdout io.Writer) error {
	config, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	if config.text == "" {
		data, err := io.ReadAll(io.LimitReader(stdin, connectorwire.MaxTextBytes+1))
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
		if len(data) > connectorwire.MaxTextBytes {
			return errors.New("stdin exceeds text byte limit")
		}
		config.text = string(data)
	}
	if config.eventID == "" {
		config.eventID, err = secureid.NewID("evt", secureid.MinIDEntropyBytes)
		if err != nil {
			return fmt.Errorf("generate event ID: %w", err)
		}
	}
	if config.messageRef == "" {
		config.messageRef, err = secureid.NewID("msg", secureid.MinIDEntropyBytes)
		if err != nil {
			return fmt.Errorf("generate message ref: %w", err)
		}
	}

	client, err := connectorhttp.NewClient(config.socket, requestTimeout)
	if err != nil {
		return fmt.Errorf("create connector client: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, config.wait)
	defer cancel()
	event := connectorwire.InboundEventV1{
		EventID:          config.eventID,
		ActorRef:         config.actor,
		ConversationRef:  config.conversation,
		MessageRef:       config.messageRef,
		OccurredAtUnixMS: time.Now().UTC().UnixMilli(),
		Content: connectorwire.InboundContentV1{
			Type: connectorwire.ContentTypeText,
			Text: config.text,
		},
	}
	if _, err := client.Ingest(ctx, event); err != nil {
		return fmt.Errorf("ingest event: %w", err)
	}

	ticker := time.NewTicker(claimInterval)
	defer ticker.Stop()
	for {
		claimCtx, claimCancel := context.WithTimeout(ctx, requestTimeout)
		result, claimErr := client.Claim(claimCtx, connectorwire.DeliveryClaimV1{Limit: 1})
		claimCancel()
		if claimErr != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("wait for reply: %w", ctx.Err())
			}
			return fmt.Errorf("claim reply: %w", claimErr)
		}
		if len(result.Deliveries) > 0 {
			delivery := result.Deliveries[0]
			if _, err := fmt.Fprintln(stdout, delivery.Content.Text); err != nil {
				return fmt.Errorf("write reply: %w", err)
			}
			providerRef, err := secureid.NewID("fake", secureid.MinIDEntropyBytes)
			if err != nil {
				return fmt.Errorf("generate provider message ref: %w", err)
			}
			completeCtx, completeCancel := context.WithTimeout(ctx, requestTimeout)
			err = client.Complete(completeCtx, connectorwire.DeliveryCompleteV1{
				DeliveryID:         delivery.DeliveryID,
				LeaseToken:         delivery.LeaseToken,
				Outcome:            connectorwire.DeliveryDelivered,
				ProviderMessageRef: providerRef,
			})
			completeCancel()
			if err != nil {
				return fmt.Errorf("complete reply: %w", err)
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for reply: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("fake-connector", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var config options
	flags.StringVar(&config.socket, "socket", "", "agentd connector Unix socket")
	flags.StringVar(&config.actor, "actor", defaultActor, "opaque actor ref")
	flags.StringVar(&config.conversation, "conversation", defaultConversation, "opaque conversation ref")
	flags.StringVar(&config.eventID, "event-id", "", "stable event ID for replay testing")
	flags.StringVar(&config.messageRef, "message-ref", "", "stable message ref")
	flags.StringVar(&config.text, "text", "", "message text; stdin when empty")
	flags.DurationVar(&config.wait, "wait", 30*time.Second, "maximum wait for one reply")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("positional arguments are not supported")
	}
	if config.socket == "" {
		return options{}, errors.New("-socket is required")
	}
	if config.wait < time.Second || config.wait > 24*time.Hour {
		return options{}, errors.New("-wait must be between 1s and 24h")
	}
	return config, nil
}
