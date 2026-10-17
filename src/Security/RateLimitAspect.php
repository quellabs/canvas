<?php

	namespace Quellabs\Canvas\Security;

	use Quellabs\Canvas\AOP\Contracts\AfterAspectInterface;
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Quellabs\Canvas\Exceptions\RateLimitException;
	use Quellabs\Canvas\Exceptions\RateLimitStoreUnavailableException;
	use Quellabs\Canvas\Security\RateLimit\RateLimitResult;
	use Quellabs\Canvas\Security\RateLimit\RateLimitStoreInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * Rate limiting aspect using various strategies
	 *
	 * Admission itself (read count, decide, write count back) is delegated to a
	 * RateLimitStoreInterface as a single atomic operation. This aspect used to
	 * perform that as two separate CacheInterface calls (get() then set()), which
	 * let concurrent requests read the same count and both be admitted - atomic
	 * individual cache operations don't make that two-call sequence atomic.
	 */
	readonly class RateLimitAspect implements BeforeAspectInterface, AfterAspectInterface {

		/** @var string[] Valid rate limiting strategies */
		private const array VALID_STRATEGIES = ['fixed_window', 'sliding_window', 'token_bucket'];

		/** @var string[] Valid rate limiting scopes */
		private const array VALID_SCOPES = ['ip', 'user', 'api_key', 'global', 'custom'];

		/** @var string[] Valid policies for when the store itself is unavailable */
		private const array VALID_STORE_FAILURE_POLICIES = ['closed', 'open'];

		/** @var RateLimitStoreInterface Atomic admission storage */
		private RateLimitStoreInterface $store;

		/** @var int Requests per window */
		private int $limit;

		/** @var int Window in seconds */
		private int $window;

		/** @var string Rate limiting strategy */
		private string $strategy;

		/** @var string Rate limiting scope */
		private string $scope;

		/** @var string Custom identifier */
		private string $identifier;

		/** @var string[] HTTP methods exempt from rate limiting */
		private array $exemptMethods;

		/** @var string Rate limit header prefix */
		private string $headerPrefix;

		/** @var bool If true, throws RateLimitException on failure instead of writing to request attributes */
		private bool $throwOnFailure;

		/** @var string What to do when the store itself is unavailable: 'closed' (block) or 'open' (bypass) */
		private string $onStoreFailure;

		/**
		 * RateLimitAspect constructor
		 * @param RateLimitStoreInterface $store
		 * @param int $limit
		 * @param int $window
		 * @param string $strategy
		 * @param string $scope
		 * @param string $identifier
		 * @param string[] $exemptMethods
		 * @param string $headerPrefix
		 * @param bool $throwOnFailure If true, throws RateLimitException on failure
		 * @param string $onStoreFailure 'closed' blocks the request when the store is unavailable
		 *   (safe default for limits protecting sensitive operations); 'open' bypasses rate limiting
		 *   for that request instead, without inventing or resetting any counter
		 */
		public function __construct(
			RateLimitStoreInterface $store,
			int                     $limit = 60,
			int                     $window = 3600,
			string                  $strategy = 'fixed_window',
			string                  $scope = 'ip',
			string                  $identifier = '',
			array                   $exemptMethods = ['GET', 'HEAD', 'OPTIONS'],
			string                  $headerPrefix = 'X-RateLimit',
			bool                    $throwOnFailure = false,
			string                  $onStoreFailure = 'closed'
		) {
			$this->store = $store;
			$this->limit = $limit;
			$this->window = $window;
			$this->strategy = $strategy;
			$this->scope = $scope;
			$this->identifier = $identifier;
			$this->exemptMethods = $exemptMethods;
			$this->headerPrefix = $headerPrefix;
			$this->throwOnFailure = $throwOnFailure;
			$this->onStoreFailure = $onStoreFailure;

			// Validate limit and window correctness
			if ($limit <= 0 || $window <= 0) {
				throw new \InvalidArgumentException('Limit and window must be positive integers');
			}

			// Validate strategy
			if (!in_array($strategy, self::VALID_STRATEGIES, true)) {
				throw new \InvalidArgumentException('Invalid strategy: ' . $strategy);
			}

			// Validate scope
			if (!in_array($scope, self::VALID_SCOPES, true)) {
				throw new \InvalidArgumentException("Invalid scope '{$scope}'. Valid options: " . implode(', ', self::VALID_SCOPES));
			}

			// Validate custom scope has identifier
			if ($scope === 'custom' && empty($identifier)) {
				throw new \InvalidArgumentException("Custom scope requires a non-empty identifier");
			}

			// Validate store failure policy
			if (!in_array($onStoreFailure, self::VALID_STORE_FAILURE_POLICIES, true)) {
				throw new \InvalidArgumentException(
					"Invalid onStoreFailure '{$onStoreFailure}'. Valid options: " . implode(', ', self::VALID_STORE_FAILURE_POLICIES)
				);
			}
		}

		/**
		 * Middleware method that executes before the main request handler
		 * Implements rate limiting with multiple strategies and HTTP header management
		 * @param MethodContextInterface $context The request context containing request data
		 * @return Response|null Returns Response if rate limit exceeded, null to continue
		 * @throws RateLimitStoreUnavailableException When the store is unavailable and onStoreFailure is 'closed'
		 */
		public function before(MethodContextInterface $context): ?Response {
			// Fetch the request from the MethodContext
			$request = $context->getRequest();

			// Skip rate limiting for exempt HTTP methods (e.g., OPTIONS, HEAD)
			// This allows certain methods to bypass rate limiting entirely
			if (in_array($request->getMethod(), $this->exemptMethods, true)) {
				return null; // No rate limiting applied, continue processing
			}

			// Generate a unique key for this request (typically based on IP, user ID, etc.)
			$key = $this->generateKey($context);

			// Get current timestamp for rate limit calculations
			$currentTime = time();

			// Delegate the admission decision to the store as a single atomic operation.
			// A storage failure never falls through to a fabricated result: it's either
			// bypassed explicitly (onStoreFailure='open') or propagated (the default).
			try {
				$result = match ($this->strategy) {
					'fixed_window' => $this->store->incrementFixedWindow($key, $this->limit, $this->window, $currentTime),
					'sliding_window' => $this->store->admitSlidingWindow($key, $this->limit, $this->window, $currentTime),
					'token_bucket' => $this->store->admitTokenBucket($key, $this->limit, $this->window, $currentTime),
					default => throw new \LogicException("Unhandled rate limit strategy: {$this->strategy}")
				};
			} catch (RateLimitStoreUnavailableException $e) {
				if ($this->onStoreFailure === 'open') {
					// Fail open: bypass rate limiting for this request. Deliberately does not
					// write any rate_limit_* attributes, since no admission decision was made.
					return null;
				}

				// Fail closed (default): the backend outage itself surfaces as a 503,
				// through the same exception-handling path as any other HttpException.
				throw $e;
			}

			// Prepare rate limit headers for the response
			// These headers inform the client about their current rate limit status
			$headers = $this->buildHeaders($result);

			// Set result
			$request->attributes->set('rate_limit_headers', $headers);
			$request->attributes->set('rate_limit_result', $result);
			$request->attributes->set('rate_limit_strategy', $this->strategy);
			$request->attributes->set('rate_limit_exceeded', $result->isExceeded());

			// Throw exception if exceeded
			if ($result->isExceeded() && $this->throwOnFailure) {
				throw new RateLimitException(
					limit: $this->limit,
					remaining: max(0, $this->limit - $result->getCount()),
					retryAfter: $result->getRetryAfter(),
					resetTime: $result->getResetTime(),
					strategy: $this->strategy,
					scope: $this->scope,
					headers: $headers
				);
			}

			// Continue to controller
			return null;
		}

		/**
		 * Apply rate limit headers to the outgoing HTTP response.
		 * @param MethodContextInterface $context Current method execution context.
		 * @param Response $response HTTP response being returned to the client.
		 * @return void
		 */
		public function after(MethodContextInterface $context, Response $response): void {
			// Retrieve rate limit headers prepared during the before() phase.
			// These are stored on the request attributes to share state between
			// the before and after aspect lifecycle stages.
			$headers = $context
				->getRequest()
				->attributes
				->get('rate_limit_headers');

			// If no headers are present, there is nothing to apply.
			if ($headers === null) {
				return;
			}

			// Assert the type stored in the before() phase. Malformed cache entries are skipped.
			if (!is_array($headers)) {
				return;
			}

			// Apply each prepared rate limit header to the outgoing response.
			// Values are cast to string to ensure compatibility with the
			// Symfony response header bag implementation.
			// array_keys() yields string|int (not mixed), making (string) cast on $name valid.
			// The value is read into a local and guarded with is_scalar() before casting,
			// because $headers is array (not array<string, scalar>) so offsets return mixed.
			foreach (array_keys($headers) as $name) {
				$value = $headers[$name];
				$response->headers->set((string)$name, is_scalar($value) ? (string)$value : '');
			}
		}

		/**
		 * Build the response headers describing the current rate limit state
		 * @param RateLimitResult $result
		 * @return array<string, int|string>
		 */
		private function buildHeaders(RateLimitResult $result): array {
			$headers = [
				// Maximum number of requests allowed in the time window
				"{$this->headerPrefix}-Limit"     => $this->limit,

				// Number of requests remaining in the current window
				// Ensures it never goes below 0 for clean header values
				"{$this->headerPrefix}-Remaining" => max(0, $this->limit - $result->getCount()),

				// Timestamp when the rate limit resets (Unix timestamp)
				"{$this->headerPrefix}-Reset"     => $result->getResetTime(),
			];

			// Inform the user when a retry may be attempted when limit was exceeded
			if ($result->isExceeded()) {
				$headers['Retry-After'] = $result->getRetryAfter();
			}

			return $headers;
		}

		/**
		 * Generate cache key based on scope and identifier
		 *
		 * Creates a unique cache key that determines the granularity of rate limiting.
		 * The key format ensures proper isolation between different scopes and routes.
		 *
		 * Key format: "rate_limit:{scope}:{identifier}:{route}"
		 *
		 * Examples:
		 * - IP-based: "rate_limit:ip:192.168.1.1:UserController::login"
		 * - User-based: "rate_limit:user:12345:ApiController::getData"
		 * - API key: "rate_limit:api_key:abc123:PaymentController::process"
		 * - Global: "rate_limit:global:global:AuthController::register"
		 *
		 * @param MethodContextInterface $context The request context containing request and routing info
		 * @return string The generated cache key for rate limiting
		 */
		private function generateKey(MethodContextInterface $context): string {
			// Fetch the request from the context
			$request = $context->getRequest();

			// Base prefix for all rate limit cache keys
			// This helps organize cache entries and avoid conflicts with other cached data
			$baseKey = 'rate_limit';

			// Determine the identifier based on the configured scope
			// Each scope provides different granularity for rate limiting
			$rawIdentifier = match ($this->scope) {
				// Rate limit per IP address - useful for preventing abuse from single sources
				'ip' => $request->getClientIp() ?? 'unknown_ip',

				// Rate limit per authenticated user - allows different limits for different users
				'user' => $this->getUserIdentifier($request),

				// Rate limit per API key - useful for API quotas and partner management
				'api_key' => $request->headers->get('X-API-Key', 'anonymous') ?? 'anonymous',

				// Global rate limit - applies to all requests regardless of source
				'global' => 'global',

				// Custom identifier - allows for flexible rate limiting strategies
				'custom' => $this->identifier,

				// Default value (will never occur, but to keep phpstan happy)
				default => throw new \LogicException("Unhandled rate limit scope: {$this->scope}")
			};

			// Sanitize each component to prevent special character conflicts and cache key collisions
			$scope = $this->sanitizeKeyComponent($this->scope);
			$identifier = $this->sanitizeKeyComponent($rawIdentifier);
			$route = $this->sanitizeKeyComponent($context->getClassName() . '::' . $context->getMethodName());

			// Construct the final cache key with all components
			// This ensures unique keys for each combination of scope, identifier, and route
			return "{$baseKey}:{$scope}:{$identifier}:{$route}";
		}

		/**
		 * Sanitize cache key component to prevent collisions and ensure compatibility
		 * @param string $component The component to sanitize
		 * @return string Sanitized component safe for cache keys
		 */
		private function sanitizeKeyComponent(string $component): string {
			// Remove or replace potentially problematic characters
			// Most cache systems have restrictions on key characters
			$sanitized = preg_replace('/[^a-zA-Z0-9._-]/', '_', $component);

			// Prevent empty components which could cause collisions
			if (empty($sanitized)) {
				$sanitized = 'empty';
			}

			// Limit length to prevent excessively long keys
			if (strlen($sanitized) > 50) {
				// Use hash for long identifiers to ensure uniqueness
				$sanitized = substr($sanitized, 0, 30) . '_' . md5($component);
			}

			return $sanitized;
		}

		/**
		 * Get user identifier for rate limiting
		 * @param Request $request
		 * @return string
		 */
		protected function getUserIdentifier(Request $request): string {
			// Try to get user from session, JWT, or other auth mechanism
			if ($request->hasSession() && $request->getSession()->has('auth_user_id')) {
				// Fetch user id from session
				$userId = $request->getSession()->get('auth_user_id');

				// getSession()->get() returns mixed; guard the type before concatenation.
				return 'user_' . (is_string($userId) || is_int($userId) ? (string)$userId : 'unknown');
			}

			// Fallback to IP if no user found
			return 'anonymous_' . $request->getClientIp();
		}
	}
