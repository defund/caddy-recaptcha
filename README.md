# caddy-recaptcha

reCAPTCHA verification middleware for Caddy.

## Syntax

### v3

The reCAPTCHA response token must be supplied as form data with the key `caddy-recaptcha-response`.

```
recaptcha v3 secret {
	action [threshold] [method] path
}
```

* **secret** is the secret key
* **action** is the action
* **threshold** is the lower bound of allowed scores
	* float between 0.0 and 1.0
	* default is .5
* **method** is the request method to validate
	* one of POST, PUT, PATCH
	* default is POST
* **path** is the URL path to validate

Multiple lines can be specified within the block, which will all share the same version and secret.