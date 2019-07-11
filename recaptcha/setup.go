package recaptcha

import (
	"fmt"
	"strconv"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("recaptcha", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	rules, err := parse(c)
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)
	mid := func(next httpserver.Handler) httpserver.Handler {
		return Recaptchas{Next: next, Rules: rules}
	}
	cfg.AddMiddleware(mid)

	return nil
}

func parse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		version := c.Val()

		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		secret := c.Val()

		if version == "v3" {
			for c.NextBlock() {
				action := c.Val()
				if !c.NextArg() {
					return nil, c.ArgErr()
				}

				recaptcha := V3Rule{Secret: secret, Action: action}

				threshold, err := strconv.ParseFloat(c.Val(), 64)
				if err != nil {
					recaptcha.Threshold = .5
				} else if !(threshold >= 0 && threshold <= 1) {
					return nil, fmt.Errorf("Invalid threshold %f.", threshold)
				} else if !c.NextArg() {
					return nil, c.ArgErr()
				} else {
					recaptcha.Threshold = threshold
				}

				method := c.Val()
				if !(method == "POST" || method == "PUT" || method == "PATCH") {
					recaptcha.Method = "POST"
				} else if !c.NextArg() {
					return nil, c.ArgErr()
				} else {
					recaptcha.Method = method
				}

				path := c.Val()
				recaptcha.Path = path

				args := c.RemainingArgs()
				if len(args) != 0 {
					return nil, c.ArgErr()
				}

				rules = append(rules, recaptcha)
			}
		} else if version == "v2" {
			for c.NextBlock() {
				recaptcha := V2Rule{Secret: secret}

				method := c.Val()
				if !(method == "POST" || method == "PUT" || method == "PATCH") {
					recaptcha.Method = "POST"
				} else if !c.NextArg() {
					return nil, c.ArgErr()
				} else {
					recaptcha.Method = method
				}

				path := c.Val()
				recaptcha.Path = path

				args := c.RemainingArgs()
				if len(args) != 0 {
					return nil, c.ArgErr()
				}

				rules = append(rules, recaptcha)
			}
		} else {
			return nil, fmt.Errorf("Invalid version %s.", version)
		}
	}

	return rules, nil
}
