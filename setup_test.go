package recaptcha

import (
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `recaptcha v3 secret`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}

	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, had 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	recaptchas, ok := handler.(Recaptchas)
	if !ok {
		t.Fatalf("Expected handler to be type Recaptchas, got: %#v", handler)
	}

	if !httpserver.SameNext(recaptchas.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		input      string
		shouldPass bool
		expected   []Rule
	}{
		{`recaptcha`, false, []Rule{}},
		{`recaptcha v3`, false, []Rule{}},
		{`recaptcha junk secret`, false, []Rule{}},
		{`recaptcha v3 secret`, true, []Rule{}},
		{`recaptcha v3 secret {
		}`, true, []Rule{}},
		{`recaptcha v3 secret {
			action
		}`, false, []Rule{}},
		{`recaptcha v3 secret {
			action /path
		}`, true, []Rule{
			V3Rule{"secret", "action", .5, "POST", "/path"},
		}},
		{`recaptcha v3 secret {
			action junk /path
		}`, false, []Rule{}},
		{`recaptcha v3 secret {
			action 2.0 /path
		}`, false, []Rule{}},
		{`recaptcha v3 secret {
			action -2.0 /path
		}`, false, []Rule{}},
		{`recaptcha v3 secret {
			action .6 /path
		}`, true, []Rule{
			V3Rule{"secret", "action", .6, "POST", "/path"},
		}},
		{`recaptcha v3 secret {
			action PUT /path
		}`, true, []Rule{
			V3Rule{"secret", "action", .5, "PUT", "/path"},
		}},
		{`recaptcha v3 secret {
			action .6 PUT /path
		}`, true, []Rule{
			V3Rule{"secret", "action", .6, "PUT", "/path"},
		}},
		{`recaptcha v3 secret {
			action /path
			action /path
			action .6 /path
			action PUT /path
			action .6 PUT /path
		}`, true, []Rule{
			V3Rule{"secret", "action", .5, "POST", "/path"},
			V3Rule{"secret", "action", .5, "POST", "/path"},
			V3Rule{"secret", "action", .6, "POST", "/path"},
			V3Rule{"secret", "action", .5, "PUT", "/path"},
			V3Rule{"secret", "action", .6, "PUT", "/path"},
		}},
		{`recaptcha v2 secret {
			/path
		}`, true, []Rule{
			V2Rule{"secret", "POST", "/path"},
		}},
		{`recaptcha v2 secret {
			junk /path
		}`, false, []Rule{}},
		{`recaptcha v2 secret {
			PUT /path
		}`, true, []Rule{
			V2Rule{"secret", "PUT", "/path"},
		}},
		{`recaptcha v3 secret {
			action /path
			action /path
		}
		recaptcha v3 secret_ {
			action .6 /path
			action PUT /path
			action .6 PUT /path
		}
		recaptcha v2 secret {
			/path
			/path
		}
		recaptcha v2 secret_ {
			PUT /path
		}`, true, []Rule{
			V3Rule{"secret", "action", .5, "POST", "/path"},
			V3Rule{"secret", "action", .5, "POST", "/path"},
			V3Rule{"secret_", "action", .6, "POST", "/path"},
			V3Rule{"secret_", "action", .5, "PUT", "/path"},
			V3Rule{"secret_", "action", .6, "PUT", "/path"},
			V2Rule{"secret", "POST", "/path"},
			V2Rule{"secret", "POST", "/path"},
			V2Rule{"secret_", "PUT", "/path"},
		}},
	}

	for i, test := range tests {
		actual, err := parse(caddy.NewTestController("http", test.input))

		if err != nil && test.shouldPass {
			t.Errorf("Test %d didn't pass, but it should have; got '%v'", i, err)
		} else if err == nil && !test.shouldPass {
			t.Errorf("Test %d passed, but it shouldn't have", i)
		}

		if len(actual) != len(test.expected) {
			t.Fatalf("Test %d expected %d rules, but got %d", i, len(test.expected), len(actual))
		}

		for j, expectedRule := range test.expected {
			expectedV3Rule, ok := expectedRule.(V3Rule)
			if ok {
				actualV3Rule, ok := actual[j].(V3Rule)
				if !ok {
					t.Errorf("Test %d, rule %d expected recaptcha.V3Rule, but got %T", i, j, actual[j])
				}

				if actualV3Rule.Secret != expectedV3Rule.Secret {
					t.Errorf("Test %d, rule %d expected secret %s, but got %s", i, j, actualV3Rule.Path, expectedV3Rule.Path)
				}

				if actualV3Rule.Action != expectedV3Rule.Action {
					t.Errorf("Test %d, rule %d expected action %s, but got %s", i, j, actualV3Rule.Action, expectedV3Rule.Action)
				}

				if actualV3Rule.Threshold != expectedV3Rule.Threshold {
					t.Errorf("Test %d, rule %d expected threshold %f, but got %f", i, j, actualV3Rule.Threshold, expectedV3Rule.Threshold)
				}

				if actualV3Rule.Method != expectedV3Rule.Method {
					t.Errorf("Test %d, rule %d expected method %s, but got %s", i, j, actualV3Rule.Method, expectedV3Rule.Method)
				}

				if actualV3Rule.Path != expectedV3Rule.Path {
					t.Errorf("Test %d, rule %d expected method %s, but got %s", i, j, actualV3Rule.Path, expectedV3Rule.Path)
				}
			}

			expectedV2Rule, ok := expectedRule.(V2Rule)
			if ok {
				actualV2Rule, ok := actual[j].(V2Rule)
				if !ok {
					t.Errorf("Test %d, rule %d expected recaptcha.V2Rule, but got %T", i, j, actual[j])
				}

				if actualV2Rule.Secret != expectedV2Rule.Secret {
					t.Errorf("Test %d, rule %d expected secret %s, but got %s", i, j, actualV2Rule.Path, expectedV2Rule.Path)
				}

				if actualV2Rule.Method != expectedV2Rule.Method {
					t.Errorf("Test %d, rule %d expected method %s, but got %s", i, j, actualV2Rule.Method, expectedV2Rule.Method)
				}

				if actualV2Rule.Path != expectedV2Rule.Path {
					t.Errorf("Test %d, rule %d expected method %s, but got %s", i, j, actualV2Rule.Path, expectedV2Rule.Path)
				}
			}
		}
	}
}
