<?php
	
	namespace Quellabs\Canvas\Security;
	
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Exceptions\JwtAuthenticationException;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * JWT authentication aspect that validates Bearer tokens before a method executes.
	 *
	 * Supports two failure modes, selectable at annotation time:
	 *
	 * - Attribute mode (default): on failure, sets 'jwt_error' on $request->attributes
	 *   and returns null, allowing the controller to decide how to respond.
	 *   'jwt_payload' and 'jwt_user_id' are set on success.
	 *
	 * - Exception mode ($throwOnFailure = true): throws JwtAuthenticationException,
	 *   which propagates to the kernel's error handler. Requires a registered
	 *   ErrorHandlerInterface that handles JwtAuthenticationException to produce
	 *   a proper JSON 401 response; the default handler returns HTML.
	 *
	 * Usage:
	 * @InterceptWith(Quellabs\Canvas\Security\JwtAuthenticationAspect::class, secret="...")
	 * @InterceptWith(Quellabs\Canvas\Security\JwtAuthenticationAspect::class, secret="...", throwOnFailure=true)
	 */
	class JwtAuthenticationAspect implements BeforeAspectInterface {
		
		/**
		 * HMAC secret for HS256, or PEM public key for RS256
		 * @var string
		 */
		private string $secret;
		
		/**
		 * When true, throws JwtAuthenticationException on failure instead of
		 * writing to request attributes. Requires a matching ErrorHandlerInterface
		 * to produce a proper JSON response; the default handler returns HTML.
		 * @var bool
		 */
		private bool $throwOnFailure;
		
		/**
		 * JwtAuthenticationAspect constructor
		 * @param string $secret HMAC secret for HS256, or PEM public key for RS256
		 * @param string $algorithm Signing algorithm (currently only HS256 is supported)
		 * @param bool $throwOnFailure When true, throws on failure instead of setting request attributes
		 */
		public function __construct(
			string $secret,
			string $algorithm = 'HS256',
			bool $throwOnFailure = false
		) {
			// RS256/ES256 require asymmetric key handling and a different validation path;
			// reject early rather than silently falling back to an insecure comparison
			if ($algorithm !== 'HS256') {
				throw new \InvalidArgumentException(
					"Unsupported algorithm '{$algorithm}'. Only HS256 is currently supported."
				);
			}
			
			$this->secret = $secret;
			$this->throwOnFailure = $throwOnFailure;
		}
		
		/**
		 * Validate the Bearer token before the controller method runs.
		 *
		 * On success: sets 'jwt_payload' (full claims array) and 'jwt_user_id' ('sub' claim)
		 * on $request->attributes, returns null.
		 *
		 * On failure in attribute mode: sets 'jwt_error' (reason string) on $request->attributes,
		 * clears 'jwt_payload' and 'jwt_user_id', returns null.
		 *
		 * On failure in exception mode: throws JwtAuthenticationException.
		 *
		 * @param MethodContextInterface $context
		 * @return Response|null Always null — this aspect never short-circuits via Response.
		 * @throws JwtAuthenticationException When throwOnFailure is true and validation fails.
		 */
		public function before(MethodContextInterface $context): ?Response {
			$request = $context->getRequest();
			
			try {
				// Symfony's HeaderBag::get() returns null when the header is absent;
				// normalise to an empty string so extractAndValidate() can apply a
				// single uniform "missing header" check rather than handling null separately
				$payload = $this->extractAndValidate($request->headers->get('Authorization') ?? '');
			} catch (JwtAuthenticationException $e) {
				if ($this->throwOnFailure) {
					throw $e;
				}
				
				// Attribute mode: record the reason and clear any stale auth attributes
				// so downstream aspects and the controller see a consistent unauthenticated state
				$request->attributes->set('jwt_error', $e->getMessage());
				$request->attributes->remove('jwt_payload');
				$request->attributes->remove('jwt_user_id');
				return null;
			}
			
			// Token is valid — publish the claims and the subject identifier so controllers
			// and downstream aspects can read them without re-parsing the token
			$request->attributes->set('jwt_payload', $payload);
			$request->attributes->set('jwt_user_id', $payload['sub'] ?? null);
			
			// Clear any jwt_error left over from a previous attempt on the same request object
			$request->attributes->remove('jwt_error');
			return null;
		}
		
		/**
		 * Parse the Authorization header, validate the token, and return its claims.
		 * @param string $authHeader Raw value of the Authorization header.
		 * @return array<string, mixed> Validated JWT claims.
		 * @throws JwtAuthenticationException On any validation failure.
		 */
		private function extractAndValidate(string $authHeader): array {
			// Require the Bearer scheme; reject Basic auth, API key headers, and empty values
			if (!str_starts_with($authHeader, 'Bearer ')) {
				throw new JwtAuthenticationException('Missing or malformed Authorization header');
			}
			
			// Strip the 'Bearer ' prefix to isolate the raw token string
			$token = substr($authHeader, 7);
			
			// A well-formed JWT is exactly three base64url segments separated by dots
			$parts = explode('.', $token);
			
			if (count($parts) !== 3) {
				throw new JwtAuthenticationException('Malformed JWT structure');
			}
			
			[$headerB64, $payloadB64, $signatureB64] = $parts;
			
			// Validate the signature before decoding the payload to avoid processing
			// attacker-controlled data before we know the token is authentic
			$this->validateSignature($headerB64, $payloadB64, $signatureB64);
			
			// Decode the payload segment from base64url to a raw JSON string;
			// strtr maps the URL-safe alphabet (-_) back to the standard alphabet (+/)
			$decoded = base64_decode(strtr($payloadB64, '-_', '+/'), true);
			
			// base64_decode returns false on malformed input (odd padding, illegal characters)
			if ($decoded === false) {
				throw new JwtAuthenticationException('Invalid JWT payload encoding');
			}
			
			$payload = json_decode($decoded, true);
			
			// json_decode returns null on parse failure, or a scalar for non-object JSON;
			// a valid JWT payload is always a JSON object, which decodes to an array here
			if (!is_array($payload)) {
				throw new JwtAuthenticationException('Invalid JWT payload');
			}
			
			// Narrow array<mixed, mixed> to array<string, mixed>: JWT claim names are always
			// strings per RFC 7519, so integer keys cannot appear in a legitimate token.
			// Filtering enforces this at runtime rather than relying on a bare @var assertion.
			/** @var array<string, mixed> $payload */
			$payload = array_filter($payload, fn($k) => is_string($k), ARRAY_FILTER_USE_KEY);
			
			// Validate time-based claims (exp, nbf, iat) now that the signature is confirmed
			$this->validateClaims($payload);
			
			return $payload;
		}
		
		/**
		 * Verify the HMAC-SHA256 signature against the header.payload input.
		 * @param string $headerB64 Base64url-encoded header segment.
		 * @param string $payloadB64 Base64url-encoded payload segment.
		 * @param string $signatureB64 Base64url-encoded signature segment.
		 * @throws JwtAuthenticationException When the signature does not match.
		 */
		private function validateSignature(string $headerB64, string $payloadB64, string $signatureB64): void {
			// Recompute the expected signature over the original header.payload input,
			// exactly as the issuer would have done when creating the token
			$expected = hash_hmac('sha256', $headerB64 . '.' . $payloadB64, $this->secret, true);
			
			// Decode the signature the token actually carries
			$provided = base64_decode(strtr($signatureB64, '-_', '+/'), true);
			
			// hash_equals performs a constant-time comparison to prevent timing attacks;
			// a plain === would leak information about how many bytes match
			if ($provided === false || !hash_equals($expected, $provided)) {
				throw new JwtAuthenticationException('Invalid JWT signature');
			}
		}
		
		/**
		 * Validate the standard time-based claims (exp, nbf, iat).
		 * @param array<string, mixed> $payload Decoded JWT claims.
		 * @throws JwtAuthenticationException When any time claim is violated.
		 */
		private function validateClaims(array $payload): void {
			$now = time();
			
			if (isset($payload['exp'])) {
				// exp must be an integer Unix timestamp per RFC 7519 §4.1.4
				if (!is_int($payload['exp'])) {
					throw new JwtAuthenticationException('Invalid exp claim');
				}
				
				// Token has passed its expiry time
				if ($payload['exp'] < $now) {
					throw new JwtAuthenticationException('JWT has expired');
				}
			}
			
			if (isset($payload['nbf'])) {
				// nbf must be an integer Unix timestamp per RFC 7519 §4.1.5
				if (!is_int($payload['nbf'])) {
					throw new JwtAuthenticationException('Invalid nbf claim');
				}
				
				// Token is not yet valid; the issuer intends it for future use
				if ($payload['nbf'] > $now) {
					throw new JwtAuthenticationException('JWT is not yet valid');
				}
			}
			
			// iat carries no enforcement logic here but must be a valid integer if present;
			// a non-integer value indicates a malformed token rather than a legitimate one
			if (isset($payload['iat']) && !is_int($payload['iat'])) {
				throw new JwtAuthenticationException('Invalid iat claim');
			}
		}
	}