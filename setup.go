package recaptcha

import (
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
				recaptcha := V3Rule{Secret: secret, Action: action}

				args := c.RemainingArgs()
				if len(args) == 2 {
					threshold, err := strconv.ParseFloat(args[0], 64)
					if err != nil {
						return nil, err
					}
					recaptcha.Threshold = threshold
					recaptcha.Path = args[1]
				} else if len(args) == 1 {
					recaptcha.Threshold = .5
					recaptcha.Path = args[0]
				} else {
					return nil, c.ArgErr()
				}

				rules = append(rules, recaptcha)
			}
		}
	}

	return rules, nil
}
