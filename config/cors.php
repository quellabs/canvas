<?php

	// Read by Quellabs\Canvas\Security\Policies\CorsSecurityHeaderPolicy, which must be
	// added to config/app.php's security_header_policy (this file alone does nothing).
	// Absent entries default to empty/false/0, so an unfilled file grants no cross-origin
	// access. Only exact http(s) origins are accepted — wildcard '*' and the opaque 'null'
	// origin are not supported.

	return [
		// Exact scheme+host(+port) origins allowed cross-origin access, e.g.
		// 'https://app.example.com' or 'https://admin.example.com:8443'.
		'allowed_origins'   => [],

		// HTTP methods allowed cross-origin, e.g. ['GET', 'POST', 'PATCH', 'DELETE'].
		'allowed_methods'   => [],

		// Request headers a cross-origin script may send, e.g. ['Content-Type', 'Authorization'].
		'allowed_headers'   => [],

		// Response headers exposed to cross-origin scripts via Access-Control-Expose-Headers.
		'exposed_headers'   => [],

		// Whether to send Access-Control-Allow-Credentials: true for allowed origins.
		'allow_credentials' => false,

		// Access-Control-Max-Age in seconds (how long a browser may cache a preflight
		// result). 0 omits the header.
		'max_age'           => 0,
	];
