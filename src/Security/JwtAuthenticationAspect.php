<?php
	
	namespace Quellabs\Canvas\Security;
	
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Exceptions\JwtAuthenticationException;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Quellabs\Contracts\Configuration\ConfigProviderInterface;
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
	 * Configuration is loaded from config/jwt.php (and config/jwt.local.php for
	 * environment-specific overrides). All constructor parameters except $configLoader
	 * are optional annotation overrides that take precedence over config file values.
	 *
	 * config/jwt.php keys:
	 *   secret           — required, set the real value in config/jwt.local.php
	 *   algorithm        — defaults to 'HS256'
	 *   throw_on_failure — defaults to false
	 *   clock_skew       — defaults to 30 (seconds, must be >= 0)
	 *   issuer           — defaults to '' (not validated when empty)
	 *   audience         — defaults to '' (not validated when empty)
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
		 * Must be >= 0.
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
		 * @param ConfigProviderInterface $configLoader Config loader, used to load config/jwt.php
		 * @param string $secret HMAC secret override; falls back to secret in config/jwt.php
		 * @param string $algorithm Algorithm override; falls back to algorithm in config/jwt.php
		 * @param bool|null $throwOnFailure Failure mode override; falls back to throw_on_failure in config/jwt.php
		 * @param int|null $clockSkew Clock skew override in seconds (>= 0); falls back to clock_skew in config/jwt.php
		 * @param string $issuer Expected issuer override; falls back to issuer in config/jwt.php
		 * @param string $audience Expected audience override; falls back to audience in config/jwt.php
		 */
		public function __construct(
			ConfigProviderInterface $configLoader,
			string $secret = '',
			string $algorithm = '',
			?bool $throwOnFailure = null,
			?int $clockSkew = null,
			string $issuer = '',
			string $audience = ''
		) {
			// Load config/jwt.php (and config/jwt.local.php if present).
			// If neither file exists, $config is an empty config object and all
			// get() calls return their defaults — the missing secret check below
			// catches this case and fails with a clear error message.
			$config = $configLoader->loadConfigFile('jwt.php');
			
			// Fetch data from config file
			$resolvedAlgorithm = $algorithm ?: $config->get('algorithm', 'HS256');
			$resolvedSecret = $secret ?: $config->get('secret', '');
			$resolvedThrowOnFailure = $throwOnFailure ?? $config->get('throw_on_failure', false);
			$resolvedClockSkew = $clockSkew ?? $config->get('clock_skew', 30);
			$resolvedIssuer = $issuer ?: $config->get('issuer', '');
			$resolvedAudience = $audience ?: $config->get('audience', '');
			
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
					"JWT secret is not configured. Set 'secret' in config/jwt.local.php."
				);
			}
			
			// Negative clock skew would reverse the intended expiry logic — a negative value
			// for exp would require the token to have expired before it is accepted, and a
			// negative value for nbf would require the token to not yet be valid in the future;
			// both are almost certainly misconfiguration rather than intentional behaviour
			if ($resolvedClockSkew < 0) {
				throw new \InvalidArgumentException(
					"Clock skew must be >= 0, got {$resolvedClockSkew}."
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
		 * Delegates base64url decoding to base64UrlDecode() and handles JSON parsing,
		 * so all base64url normalisation logic lives in one place.
		 *
		 * @param string $segment Base64url-encoded JWT segment (header or payload).
		 * @return array<string, mixed> Decoded segment as an associative array.
		 * @throws JwtAuthenticationException On malformed base64url input or invalid JSON.
		 */
		private function decodeSegment(string $segment): array {
			$decoded = $this->base64UrlDecode($segment);
			
			// base64UrlDecode returns false on malformed input (illegal characters, bad padding)
			if ($decoded === false) {
				throw new JwtAuthenticationException('Invalid JWT segment encoding');
			}
			
			try {
				// JSON_THROW_ON_ERROR ensures malformed JSON throws rather than returning null,
				// avoiding a separate null check and making the failure reason explicit
				$data = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
			} catch (\JsonException) {
				throw new JwtAuthenticationException('Invalid JWT segment JSON');
			}
			
			// With assoc=true, both JSON objects and JSON arrays decode to PHP arrays.
			// JWT headers and payloads must be JSON objects per RFC 7519 §3, so list
			// arrays (i.e. JSON arrays) are explicitly rejected here.
			if (!is_array($data) || array_is_list($data)) {
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
			
			// Decode the signature the token actually carries using the shared base64url decoder
			$provided = $this->base64UrlDecode($signatureB64);
			
			// hash_equals performs a constant-time comparison to prevent timing attacks;
			// a plain === would leak information about how many bytes match
			if ($provided === false || !hash_equals($expected, $provided)) {
				throw new JwtAuthenticationException('Invalid JWT signature');
			}
		}
		
		/**
		 * Decode a base64url-encoded value to raw bytes.
		 *
		 * JWT uses unpadded base64url encoding. This method restores the standard base64
		 * alphabet and padding before decoding, and is used for all three JWT segments so
		 * the normalisation logic is not duplicated.
		 *
		 * @param string $value Base64url-encoded value.
		 * @return string|false Decoded bytes, or false on malformed input.
		 */
		private function base64UrlDecode(string $value): string|false {
			// Restore standard base64 alphabet from base64url (-_ -> +/)
			$value = strtr($value, '-_', '+/');
			
			// Restore padding stripped by the JWT encoder; base64 requires length % 4 === 0
			$padding = strlen($value) % 4;
			
			if ($padding !== 0) {
				$value .= str_repeat('=', 4 - $padding);
			}
			
			return base64_decode($value, true);
		}
		
		/**
		 * Validate the standard time-based claims (exp, nbf, iat) and optional
		 * issuer and audience claims.
		 *
		 * NumericDate values (exp, nbf, iat) accept both int and float per RFC 7519,
		 * since some JWT issuers emit floating-point timestamps. Values are cast to int
		 * before comparison so fractional seconds do not affect validation logic.
		 *
		 * @param array<string, mixed> $payload Decoded JWT claims.
		 * @throws JwtAuthenticationException When any claim is violated.
		 */
		private function validateClaims(array $payload): void {
			$now = time();
			
			if (isset($payload['exp'])) {
				// RFC 7519 §2 defines NumericDate as a JSON numeric value (integer or float);
				// some issuers emit 1717000000.0 rather than 1717000000, so both are accepted
				if (!is_int($payload['exp']) && !is_float($payload['exp'])) {
					throw new JwtAuthenticationException('Invalid exp claim');
				}
				
				// Allow clock skew to compensate for minor time differences between
				// the token issuer and this server; subtract skew from now so that
				// tokens expired by less than $clockSkew seconds are still accepted
				if ((int)$payload['exp'] < ($now - $this->clockSkew)) {
					throw new JwtAuthenticationException('JWT has expired');
				}
			}
			
			if (isset($payload['nbf'])) {
				// Accept both int and float for the same interoperability reason as exp
				if (!is_int($payload['nbf']) && !is_float($payload['nbf'])) {
					throw new JwtAuthenticationException('Invalid nbf claim');
				}
				
				// Allow clock skew in the opposite direction; add skew to now so that
				// tokens not-before'd up to $clockSkew seconds in the future are accepted
				if ((int)$payload['nbf'] > ($now + $this->clockSkew)) {
					throw new JwtAuthenticationException('JWT is not yet valid');
				}
			}
			
			if (isset($payload['iat'])) {
				// Accept both int and float for the same interoperability reason as exp;
				// iat carries no enforcement logic here but must be a valid numeric type
				if (!is_int($payload['iat']) && !is_float($payload['iat'])) {
					throw new JwtAuthenticationException('Invalid iat claim');
				}
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
				
				if (is_array($aud)) {
					// Validate that all elements are strings before searching — a malformed
					// aud array with non-string elements should be rejected rather than
					// silently failing to match
					foreach ($aud as $entry) {
						if (!is_string($entry)) {
							throw new JwtAuthenticationException('Invalid JWT audience');
						}
					}
					
					$audMatches = in_array($this->audience, $aud, true);
				} else {
					$audMatches = $aud === $this->audience;
				}
				
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