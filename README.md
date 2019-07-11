# caddy-recaptcha

reCAPTCHA verification middleware for Caddy.

The recaptcha directive performs reCAPTCHA validation on incoming requests. Upon receiving a specified type of request, it extracts the response token and sends it to the reCAPTCHA server. If the request is invalid, recaptcha drops it and returns a 400 status code.

This allows backends to simplify their code and logic. However, the recaptcha directive does not inject reCAPTCHA code into outgoing HTML pages. Instead, that can be done with the http.filter plugin.

Note: Do the nature of reCAPTCHA, automated testing is not possible for much of caddy-captcha's functionality. Rigorous manual testing was conducted instead.

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
