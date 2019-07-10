package recaptcha

import (
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

type Recaptchas struct {
	Next  httpserver.Handler
	Rules []Rule
}

type Rule interface {
	Validate(r *http.Request) bool
}

func (h Recaptchas) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range h.Rules {
		if !rule.Validate(r) {
			return 400, errors.New("Failed to validate reCAPTCHA.")
		}
	}

	return h.Next.ServeHTTP(w, r)
}
