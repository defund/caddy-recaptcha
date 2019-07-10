package recaptcha

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
)

type V3Rule struct {
	Secret    string
	Action    string
	Threshold float64
	Path      string
}

func (rule V3Rule) Validate(r *http.Request) bool {
	if r.URL.Path != rule.Path {
		return true
	}

	err := r.ParseForm()
	if err != nil {
		return false
	}

	response := r.PostForm.Get("caddy-recaptcha-response")
	if response == "" {
		return false
	}

	params := url.Values{}
	params.Set("secret", rule.Secret)
	params.Set("response", response)
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", params)
	if err != nil {
		return false
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if !result["success"].(bool) {
		return false
	}

	if result["action"].(string) != rule.Action {
		return false
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		return false
	}

	if result["hostname"].(string) != host {
		return false
	}

	if result["score"].(float64) < rule.Threshold {
		return false
	}

	return true
}
