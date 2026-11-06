<?php

	return [
		// HMAC secret used to verify token signatures.
		// Leave empty here — set the real value in config/jwt.local.php,
		// which should not be committed to source control.
		'secret'           => '',

		// Signing algorithm. Only HS256 is currently supported.
		'algorithm'        => 'HS256',

		// When true, authentication failures throw JwtAuthenticationException.
		// When false (default), failures set 'jwt_error' on request attributes
		// and the controller decides how to respond.
		// Requires a registered ErrorHandlerInterface to produce a proper JSON
		// response in exception mode; the default Canvas handler returns HTML.
		'throw_on_failure' => false,

		// Seconds of clock skew tolerance applied to exp and nbf claim validation.
		// Compensates for minor time differences between token issuer and this server.
		// Must be >= 0.
		'clock_skew'       => 30,

		// Expected value of the 'iss' (issuer) claim.
		// Leave empty to skip issuer validation.
		'issuer'           => '',

		// Expected value of the 'aud' (audience) claim.
		// Leave empty to skip audience validation.
		'audience'         => '',
	];
