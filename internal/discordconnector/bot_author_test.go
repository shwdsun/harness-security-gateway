package discordconnector

import "testing"

func TestBotAdmissionRequiresExactSeparateStartupAuthority(t *testing.T) {
	const tester = "444444444444444444"
	config := validConfig()
	config.AllowedBotAuthorIDs = []string{tester}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	message := testMessage()
	message.Author.ID, message.Author.Bot = tester, true
	event, skip := config.Normalize(message)
	if skip != SkipNone || event.ActorRef != ActorRef(tester) || event.ConversationRef != ConversationRef(config.ChannelID) {
		t.Fatalf("explicit bot did not preserve exact platform identity: %s %+v", skip, event)
	}
	for name, mutate := range map[string]func(*Config, *Message){
		"default policy":                  func(c *Config, _ *Message) { c.AllowedBotAuthorIDs = nil },
		"unknown bot":                     func(_ *Config, m *Message) { m.Author.ID = "555555555555555555" },
		"human list is not bot authority": func(_ *Config, m *Message) { m.Author.ID = "222222222222222222" },
		"bot list is not human authority": func(_ *Config, m *Message) { m.Author.Bot = false },
		"self":                            func(c *Config, m *Message) { m.Author.ID = c.SelfUserID },
		"system":                          func(_ *Config, m *Message) { m.Author.System = true },
		"webhook":                         func(_ *Config, m *Message) { m.WebhookID = "666666666666666666" },
		"foreign channel":                 func(_ *Config, m *Message) { m.ChannelID = "777777777777777777" },
		"empty transport probe":           func(_ *Config, m *Message) { m.Content = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c, m := config, message
			mutate(&c, &m)
			if got, reason := c.Normalize(m); reason == SkipNone || got.EventID != "" {
				t.Fatalf("admitted outside exact bot authority: %s %+v", reason, got)
			}
		})
	}
}

func TestBotStartupAuthorityRejectsAmbiguousIdentities(t *testing.T) {
	for _, ids := range [][]string{
		{"111111111111111111"}, {"222222222222222222"},
		{"444444444444444444", "444444444444444444"}, {"not-an-id"}, {"044444444444444444"},
	} {
		config := validConfig()
		config.AllowedBotAuthorIDs = ids
		if config.Validate() == nil {
			t.Fatalf("accepted ambiguous bot authority: %v", ids)
		}
	}
}
