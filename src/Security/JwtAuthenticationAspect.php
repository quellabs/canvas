<?php
	
	namespace Quellabs\Canvas\Security;
	
	use Quellabs\Canvas\Configuration\Configuration;
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Exceptions\JwtAuthenticationException;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * JWT authentication aspect that validates Bearer tokens before a method executes.
	 *
	 * Supports two failure modes, selectable per endpoint or globally via config:
	 *
	 * - Attribute mode (default): on failure, sets 'jwt_error' on $request->attributes
	 *   and returns null, allowing the controller to decide how to respond.
	 *   'jwt_payload' and 'jwt_user_id' are set on success.
	 *
	 * - Exception mode (throwOnFailure=true): throws JwtAuthenticationException,
	 *   which propagates to the kernel's error handler. Requires a registered
	 *   ErrorHandlerInterface that handles JwtAuthenticationException to produce
	 *   a proper JSON 401 response; the default handler returns HTML.
	 *
	 * All constructor parameters except $configuration are optional annotation overrides.
	 * Each falls back to the corresponding jwt.* key in config/app.php when not provided.
	 *
	 * config/app.php keys:
	 *   jwt.secret           — required, set the real value in config/app.local.php
	 *   jwt.algorithm        — defaults to 'HS256'
	 *   jwt.throw_on_failure — defaults to false
	 *   jwt.clock_skew       — defaults to 30 (seconds)
	 *   jwt.issuer           — defaults to '' (not validated when empty)
	 *   jwt.audience         — defaults to '' (not validated when empty)
	 *
	 * Usage:
	 * @InterceptWith(Quellabs\Canvas\Security\JwtAuthenticationAspect::class)
	 * @InterceptWith(Quellabs\Canvas\Security\JwtAuthenticationAspect::class, throwOnFailure=true)
	 * @InterceptWith(Quellabs\Canvas\Security\JwtAuthenticationAspect::class, secret="service-secret", issuer="service-a")
	 */
	class JwtAuthenticationAspect implements BeforeAspectInterface {
		
		/**
		 * HMAC secret used to verify the token signature
		 * @var string
		 */
		private string $secret;
		
		/**
		 * Expected signing algorithm — only HS256 is currently supported
		 * @var string
		 */
		private string $algorithm;
		
		/**
		 * When true, throws JwtAuthenticationException on failure instead of
		 * writing to request attributes. Requires a matching ErrorHandlerInterface
		 * to produce a proper JSON response; the default handler returns HTML.
		 * @var bool
		 */
		private bool $throwOnFailure;
		
		/**
		 * Number of seconds of clock skew to allow when validating exp and nbf claims.
		 * Compensates for minor time differences between token issuer and this server.
		 * @var int
		 */
		private int $clockSkew;
		
		/**
		 * Expected value of the 'iss' claim. Not validated when empty.
		 * @var string
		 */
		private string $issuer;
		
		/**
		 * Expected value of the 'aud' claim. Not validated when empty.
		 * @var string
		 */
		private string $audience;
		
		/**
		 * JwtAuthenticationAspect constructor
		 * @param Configuration $configuration Application configuration, supplies jwt.* defaults
		 * @param string $secret HMAC secret override; falls back to jwt.secret in config
		 * @param string $algorithm Algorithm override; falls back to jwt.algorithm in config
		 * @param bool|null $throwOnFailure Failure mode override; falls back to jwt.throw_on_failure in config
		 * @param int|null $clockSkew Clock skew override in seconds; falls back to jwt.clock_skew in config
		 * @param string $issuer Expected issuer override; falls back to jwt.issuer in config
		 * @param string $audience Expected audience override; falls back to jwt.audience in config
		 */
		public function __construct(
			Configuration $configuration,
			string $secret = '',
			string $algorithm = '',
			?bool $throwOnFailure = null,
			?int $clockSkew = null,
			string $issuer = '',
			string $audience = ''
		) {
			// Fetch data
			$resolvedAlgorithm = $algorithm ?: $configuration->get('jwt.algorithm', 'HS256');
			$resolvedSecret = $secret ?: $configuration->get('jwt.secret', '');
			$resolvedThrowOnFailure = $throwOnFailure ?? $configuration->get('jwt.throw_on_failure', false);
			$resolvedClockSkew = $clockSkew ?? $configuration->get('jwt.clock_skew', 30);
			$resolvedIssuer = $issuer ?: $configuration->get('jwt.issuer', '');
			$resolvedAudience = $audience ?: $configuration->get('jwt.audience', '');
			
			// RS256/ES256 require asymmetric key handling and a different validation path;
			// reject early rather than silently falling back to an insecure comparison
			if ($resolvedAlgorithm !== 'HS256') {
				throw new \InvalidArgumentException(
					"Unsupported algorithm '{$resolvedAlgorithm}'. Only HS256 is currently supported."
				);
			}
			
			// A missing secret means every token would be validated against an empty key,
			// which is a critical misconfiguration; fail hard at startup rather than silently
			if (empty($resolvedSecret)) {
				throw new \RuntimeException(
					"JWT secret is not configured. Set 'jwt.secret' in config/app.local.php."
				);
			}
			
			$this->secret = $resolvedSecret;
			$this->algorithm = $resolvedAlgorithm;
			$this->throwOnFailure = $resolvedThrowOnFailure;
			$this->clockSkew = $resolvedClockSkew;
			$this->issuer = $resolvedIssuer;
			$this->audience = $resolvedAudience;
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
		 * Note: specific failure reasons (expired, bad signature, etc.) are intentionally
		 * preserved in jwt_error and in the exception message to aid debugging. Controllers
		 * and error handlers are responsible for deciding how much detail to surface to clients.
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
			
			// Decode and validate the header before touching the signature or payload;
			// a malformed or mismatched header should fail immediately
			$header = $this->decodeSegment($headerB64);
			
			// Reject tokens that claim a different algorithm than we support — accepting
			// a token that declares 'none' or RS256 while validating as HS256 would be insecure
			if (($header['alg'] ?? null) !== $this->algorithm) {
				throw new JwtAuthenticationException('Unsupported or missing JWT algorithm');
			}
			
			// Validate the signature before decoding the payload to avoid processing
			// attacker-controlled data before we know the token is authentic
			$this->validateSignature($headerB64, $payloadB64, $signatureB64);
			
			// Decode the payload segment now that the signature is confirmed
			$payload = $this->decodeSegment($payloadB64);
			
			// Validate time-based claims and optional issuer/audience claims
			$this->validateClaims($payload);
			
			return $payload;
		}
		
		/**
		 * Decode a base64url-encoded JWT segment and return it as an associative array.
		 *
		 * JWT uses unpadded base64url encoding; PHP's base64_decode() requires standard
		 * padding, so we restore it before decoding. strtr maps the URL-safe alphabet
		 * (-_) back to the standard alphabet (+/).
		 *
		 * @param string $segment Base64url-encoded JWT segment (header or payload).
		 * @return array<string, mixed> Decoded segment as an associative array.
		 * @throws JwtAuthenticationException On malformed base64url input or invalid JSON.
		 */
		private function decodeSegment(string $segment): array {
			// Restore standard base64 alphabet from base64url
			$base64 = strtr($segment, '-_', '+/');
			
			// Restore padding stripped by the JWT encoder; base64 requires length % 4 === 0
			$padding = strlen($base64) % 4;
			
			if ($padding !== 0) {
				$base64 .= str_repeat('=', 4 - $padding);
			}
			
			$decoded = base64_decode($base64, true);
			
			// base64_decode returns false on malformed input (illegal characters, bad padding)
			if ($decoded === false) {
				throw new JwtAuthenticationException('Invalid JWT segment encoding');
			}
			
			$data = json_decode($decoded, true);
			
			// json_decode returns null on parse failure, or a scalar for non-object JSON;
			// a valid JWT header and payload are always JSON objects, which decode to arrays
			if (!is_array($data)) {
				throw new JwtAuthenticationException('Invalid JWT segment JSON');
			}
			
			// Reject any segment where a key is not a string — JWT claim names are always
			// strings per RFC 7519, so a non-string key indicates a malformed token rather
			// than something we should silently drop
			foreach (array_keys($data) as $key) {
				if (!is_string($key)) {
					throw new JwtAuthenticationException('Invalid JWT segment');
				}
			}
			
			/** @var array<string, mixed> $data */
			return $data;
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
			
			// Decode the signature the token actually carries using the same base64url decoder
			$provided = $this->base64UrlDecode($signatureB64);
			
			// hash_equals performs a constant-time comparison to prevent timing attacks;
			// a plain === would leak information about how many bytes match
			if ($provided === false || !hash_equals($expected, $provided)) {
				throw new JwtAuthenticationException('Invalid JWT signature');
			}
		}
		
		/**
		 * Decode a base64url-encoded value to raw bytes without JSON parsing.
		 * Used for the signature segment, which is binary rather than JSON.
		 * @param string $value Base64url-encoded value.
		 * @return string|false Decoded bytes, or false on malformed input.
		 */
		private function base64UrlDecode(string $value): string|false {
			// Restore standard base64 alphabet from base64url
			$value = strtr($value, '-_', '+/');
			
			// Restore padding stripped by the JWT encoder
			$padding = strlen($value) % 4;
			
			if ($padding !== 0) {
				$value .= str_repeat('=', 4 - $padding);
			}
			
			return base64_decode($value, true);
		}
		
		/**
		 * Validate the standard time-based claims (exp, nbf, iat) and optional
		 * issuer and audience claims.
		 * @param array<string, mixed> $payload Decoded JWT claims.
		 * @throws JwtAuthenticationException When any claim is violated.
		 */
		private function validateClaims(array $payload): void {
			$now = time();
			
			if (isset($payload['exp'])) {
				// exp must be an integer Unix timestamp per RFC 7519 §4.1.4
				if (!is_int($payload['exp'])) {
					throw new JwtAuthenticationException('Invalid exp claim');
				}
				
				// Allow clock skew to compensate for minor time differences between
				// the token issuer and this server; subtract skew from now so that
				// tokens expired by less than $clockSkew seconds are still accepted
				if ($payload['exp'] < ($now - $this->clockSkew)) {
					throw new JwtAuthenticationException('JWT has expired');
				}
			}
			
			if (isset($payload['nbf'])) {
				// nbf must be an integer Unix timestamp per RFC 7519 §4.1.5
				if (!is_int($payload['nbf'])) {
					throw new JwtAuthenticationException('Invalid nbf claim');
				}
				
				// Allow clock skew in the opposite direction; add skew to now so that
				// tokens not-before'd up to $clockSkew seconds in the future are accepted
				if ($payload['nbf'] > ($now + $this->clockSkew)) {
					throw new JwtAuthenticationException('JWT is not yet valid');
				}
			}
			
			// iat carries no enforcement logic here but must be a valid integer if present;
			// a non-integer value indicates a malformed token rather than a legitimate one
			if (isset($payload['iat']) && !is_int($payload['iat'])) {
				throw new JwtAuthenticationException('Invalid iat claim');
			}
			
			// Validate issuer if configured — prevents tokens issued for another service
			// from being accepted here, even if they share the same signing secret
			if (!empty($this->issuer)) {
				if (($payload['iss'] ?? null) !== $this->issuer) {
					throw new JwtAuthenticationException('Invalid JWT issuer');
				}
			}
			
			// Validate audience if configured — prevents tokens intended for another
			// audience from being accepted; aud may be a string or an array per RFC 7519
			if (!empty($this->audience)) {
				$aud = $payload['aud'] ?? null;
				
				$audMatches = $aud === $this->audience ||
					(is_array($aud) && in_array($this->audience, $aud, true));
				
				if (!$audMatches) {
					throw new JwtAuthenticationException('Invalid JWT audience');
				}
			}
			
			// Validate the sub claim type if present — the application expects a string
			// identifier; a non-string sub would produce an unexpected jwt_user_id type
			if (isset($payload['sub']) && !is_string($payload['sub'])) {
				throw new JwtAuthenticationException('Invalid sub claim');
			}
		}
	}