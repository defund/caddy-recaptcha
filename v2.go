package recaptcha

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
)

type V2Rule struct {
	Secret string
	Method string
	Path   string
}

func (rule V2Rule) Validate(r *http.Request) bool {
	if r.Method != rule.Method {
		return true
	}

	if r.URL.Path != rule.Path {
		return true
	}

	err := r.ParseForm()
	if err != nil {
		return false
	}

	response := r.PostForm.Get("g-recaptcha-response")
	if response == "" {
		response = r.Header.Get("g-recaptcha-response")
	}
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

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		return false
	}

	if result["hostname"].(string) != host {
		return false
	}

	return result["success"].(bool)
}
