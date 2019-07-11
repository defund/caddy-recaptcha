# caddy-recaptcha

reCAPTCHA verification middleware for Caddy.

caddy-recaptcha performs reCAPTCHA validation on incoming requests. This allows backends to simplify their code and logic. However, caddy-captcha does not inject reCAPTCHA code into outgoing HTML pages. This can be done relatively easily with the http.filter plugin.

The recaptcha directive specifies certain types of requests that should be validated. Upon receiving one, caddy-recaptcha extracts the response token and sends it to the reCAPTCHA server. If the request is invalid, caddy-recaptcha drops it and returns a 400 status code.

## Usage

### v3

The reCAPTCHA response token must be supplied as one of the following:
* Form data with the key `g-recaptcha-response`
* Header with the name `g-recaptcha-response`

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

Multiple lines can be specified within the block, which will all share the same secret.

### v2

The reCAPTCHA response token must be supplied as one of the following:
* Form data with the key `g-recaptcha-response`
* Header with the name `g-recaptcha-response`

```
recaptcha v2 secret {
	[method] path
}
```

* **secret** is the secret key
* **method** is the request method to validate
	* one of POST, PUT, PATCH
	* default is POST
* **path** is the URL path to validate

Multiple lines can be specified within the block, which will all share the same secret.
