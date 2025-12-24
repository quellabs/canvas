<?php
	
	namespace Quellabs\Canvas\RateLimiting;
	
	use Quellabs\Contracts\AOP\BeforeAspect;
	use Quellabs\Contracts\AOP\MethodContext;
	use Quellabs\Contracts\Cache\CacheInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Symfony\Component\HttpFoundation\JsonResponse;
	
	/**
	 * Rate limiting aspect using various strategies
	 */
	class RateLimitAspect implements BeforeAspect {
		
		/** @var string[] Valid rate limiting strategies */
		private const array VALID_STRATEGIES = ['fixed_window', 'sliding_window', 'token_bucket'];
		
		/** @var string[] Valid rate limiting scopes */
		private const array VALID_SCOPES = ['ip', 'user', 'api_key', 'global', 'custom'];
		
		/** @var CacheInterface */
		private CacheInterface $cache;
		
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
		
		/** @var array HTTP methods exempt from rate limiting */
		private array $exemptMethods;
		
		/** @var string Rate limit header prefix */
		private string $headerPrefix;
		
		/**
		 * RateLimitAspect constructor
		 * @param CacheInterface $cache
		 * @param int $limit
		 * @param int $window
		 * @param string $strategy
		 * @param string $scope
		 * @param string $identifier
		 * @param array $exemptMethods
		 * @param string $headerPrefix
		 */
		public function __construct(
			CacheInterface $cache,
			int            $limit = 60,
			int            $window = 3600,
			string         $strategy = 'fixed_window',
			string         $scope = 'ip',
			string         $identifier = '',
			array          $exemptMethods = ['GET', 'HEAD', 'OPTIONS'],
			string         $headerPrefix = 'X-RateLimit'
		) {
			$this->cache = $cache;
			$this->limit = $limit;
			$this->window = $window;
			$this->strategy = $strategy;
			$this->scope = $scope;
			$this->identifier = $identifier;
			$this->exemptMethods = $exemptMethods;
			$this->headerPrefix = $headerPrefix;
			
			if ($limit <= 0 || $window <= 0) {
				throw new \InvalidArgumentException('Limit and window must be positive integers');
			}
			
			// Validate strategy
			if (!in_array($strategy, self::VALID_STRATEGIES)) {
				throw new \InvalidArgumentException('Invalid strategy: ' . $strategy);
			}
			
			// Validate scope
			if (!in_array($scope, self::VALID_SCOPES)) {
				throw new \InvalidArgumentException("Invalid scope '$scope'. Valid options: " . implode(', ', self::VALID_SCOPES));
			}
			
			// Validate custom scope has identifier
			if ($scope === 'custom' && empty($identifier)) {
				throw new \InvalidArgumentException("Custom scope requires a non-empty identifier");
			}
		}
		
		/**
		 * Middleware method that executes before the main request handler
		 * Implements rate limiting with multiple strategies and HTTP header management
		 * @param MethodContext $context The request context containing request data
		 * @return Response|null Returns Response if rate limit exceeded, null to continue
		 */
		public function before(MethodContext $context): ?Response {
			// Fetch the request from the MethodContext
			$request = $context->getRequest();
			
			// Skip rate limiting for exempt HTTP methods (e.g., OPTIONS, HEAD)
			// This allows certain methods to bypass rate limiting entirely
			if (in_array($request->getMethod(), $this->exemptMethods)) {
				return null; // No rate limiting applied, continue processing
			}
			
			// Generate a unique key for this request (typically based on IP, user ID, etc.)
			$key = $this->generateKey($context);
			
			// Get current timestamp for rate limit calculations
			$currentTime = time();
			
			// Apply the selected rate limiting strategy using match expression
			// Each strategy returns an array with 'count', 'exceeded', and 'reset_time'
			$result = match ($this->strategy) {
				'fixed_window' => $this->fixedWindowStrategy($key, $currentTime),
				'sliding_window' => $this->slidingWindowStrategy($key, $currentTime),
				'token_bucket' => $this->tokenBucketStrategy($key, $currentTime),
				default => $this->fixedWindowStrategy($key, $currentTime) // Fallback strategy
			};
			
			// Prepare rate limit headers for the response
			// These headers inform the client about their current rate limit status
			$request->attributes->set('rate_limit_headers', [
				// Maximum number of requests allowed in the time window
				"{$this->headerPrefix}-Limit"     => $this->limit,
				
				// Number of requests remaining in the current window
				// Ensures it never goes below 0 for clean header values
				"{$this->headerPrefix}-Remaining" => max(0, $this->limit - $result['count']),
				
				// Timestamp when the rate limit resets (Unix timestamp)
				"{$this->headerPrefix}-Reset"     => $result['reset_time'],
				
				// Which rate limiting strategy is being used
				"{$this->headerPrefix}-Strategy"  => $this->strategy
			]);
			
			// Check if the rate limit has been exceeded
			if ($result['exceeded']) {
				// Create and return a rate limit exceeded response (typically 429 Too Many Requests)
				return $this->createRateLimitResponse($request, $result);
			}
			
			// Rate limit isn't exceeded, allow the request to continue to the next middleware/handler
			return null;
		}
		
		/**
		 * Fixed window strategy - resets counter at fixed intervals
		 *
		 * This strategy divides time into fixed windows (e.g., every 60 seconds) and counts
		 * requests within each window. When a window expires, the counter resets to 0.
		 *
		 * Pros: Simple, predictable, memory efficient
		 * Cons: Can allow burst traffic at window boundaries (up to 2x limit)
		 *
		 * @param string $key The unique identifier for this rate limit instance
		 * @param int $currentTime Current Unix timestamp
		 * @return array Contains count, exceeded status, reset time, and retry_after
		 */
		private function fixedWindowStrategy(string $key, int $currentTime): array {
			// Calculate the start of the current window by rounding down to nearest window boundary
			// Example: if window=60 and currentTime=1625097123, windowStart=1625097120
			$windowStart = floor($currentTime / $this->window) * $this->window;
			
			// Create a unique cache key that includes the window start time
			// This ensures each window has its own counter
			$cacheKey = "{$key}:fixed:{$windowStart}";
			
			// Get current count for this window (defaults to 0 if not found)
			$count = $this->cache->get($cacheKey, 0);
			
			// Increment the counter for this request
			$count++;
			
			// Calculate TTL: how many seconds until this window expires
			// This ensures the cache entry is automatically cleaned up when window ends
			$ttl = ($windowStart + $this->window) - $currentTime;
			
			// Store the updated count with TTL equal to remaining window duration
			$this->cache->set($cacheKey, $count, $ttl);
			
			return [
				'count'       => $count,                                    // Current request count in this window
				'exceeded'    => $count > $this->limit,                 // Whether limit is exceeded
				'reset_time'  => $windowStart + $this->window,        // When the window resets (Unix timestamp)
				'retry_after' => ($windowStart + $this->window) - $currentTime  // Seconds until reset
			];
		}
		
		/**
		 * Sliding window strategy - maintains a rolling window of requests
		 *
		 * This strategy tracks individual request timestamps within a rolling time window.
		 * Unlike fixed windows, this provides smooth rate limiting without boundary burst issues.
		 *
		 * Pros: Accurate rate limiting, no burst traffic at boundaries, fair distribution
		 * Cons: Higher memory usage (stores all timestamps), more complex cleanup logic
		 *
		 * Example: With 60-second window and 10 req/min limit:
		 * - At 12:00:30, counts requests from 11:59:30 to 12:00:30
		 * - At 12:00:45, counts requests from 11:59:45 to 12:00:45
		 *
		 * @param string $key The unique identifier for this rate limit instance
		 * @param int $currentTime Current Unix timestamp
		 * @return array Contains count, exceeded status, reset time, and retry_after
		 */
		private function slidingWindowStrategy(string $key, int $currentTime): array {
			// Create cache key for storing the sliding window timestamps
			// No window start time needed since we store individual timestamps
			$cacheKey = "{$key}:sliding";
			
			// Calculate cutoff time - requests older than this are outside the window
			// Example: if window=60 and currentTime=1625097123, cutoff=1625097063
			$cutoff = $currentTime - $this->window;
			
			// Retrieve existing timestamps array from cache (empty array if not found)
			$timestamps = $this->cache->get($cacheKey, []);
			
			// Remove expired timestamps that fall outside the current sliding window
			// This cleanup ensures we only count requests within the time window
			$timestamps = array_filter($timestamps, fn($ts) => $ts > $cutoff);
			
			// Add the current request timestamp to the window
			$timestamps[] = $currentTime;
			
			// Store the updated timestamps array back to cache
			// TTL is set to window duration since older timestamps will be filtered out
			$this->cache->set($cacheKey, $timestamps, $this->window);
			
			// Count total requests in the current sliding window
			$count = count($timestamps);
			
			return [
				'count'       => $count,                                    // Current request count in sliding window
				'exceeded'    => $count > $this->limit,                 // Whether limit is exceeded
				'reset_time'  => $currentTime + $this->window,        // When current window fully expires
				
				// Calculate retry_after: if exceeded, wait until oldest request expires
				// If not exceeded, no wait time needed
				'retry_after' => $count > $this->limit ?
					($timestamps[0] + $this->window) - $currentTime : 0
			];
		}
		
		/**
		 * Token bucket strategy - allows bursts up to bucket size
		 *
		 * This strategy maintains a "bucket" of tokens that refills at a constant rate.
		 * Each request consumes one token. When the bucket is empty, requests are rejected.
		 *
		 * Pros: Allows controlled bursts, smooth rate limiting, handles irregular traffic well
		 * Cons: More complex logic, requires floating-point calculations, persistent state
		 *
		 * Example: With 60-second window and 10 req/min limit:
		 * - Bucket starts with 10 tokens
		 * - Refills at 10/60 = 0.167 tokens per second
		 * - Client can burst 10 requests immediately, then wait for refill
		 *
		 * @param string $key The unique identifier for this rate limit instance
		 * @param int $currentTime Current Unix timestamp
		 * @return array Contains count, exceeded status, reset time, and retry_after
		 */
		private function tokenBucketStrategy(string $key, int $currentTime): array {
			// Create cache key for storing the token bucket state
			$cacheKey = "{$key}:bucket";
			
			// Calculate refill rate: how many tokens are added per second
			// Example: 10 requests per 60 seconds = 0.167 tokens per second
			$refillRate = $this->limit / $this->window;
			
			// Get existing bucket state or initialize new bucket
			$bucket = $this->cache->get($cacheKey, [
				'tokens'      => $this->limit,   // Start with full bucket
				'last_refill' => $currentTime    // Track when bucket was last refilled
			]);
			
			// Calculate how many tokens to add based on time elapsed since last refill
			$timePassed = $currentTime - $bucket['last_refill'];
			$tokensToAdd = $timePassed * $refillRate;
			
			// Refill the bucket, but don't exceed the maximum capacity
			// min() ensures we never have more tokens than the bucket size
			$bucket['tokens'] = min($this->limit, $bucket['tokens'] + $tokensToAdd);
			
			// Update the last refill time to current time
			$bucket['last_refill'] = $currentTime;
			
			// Check if request can be processed (need at least 1 token)
			$exceeded = $bucket['tokens'] < 1;
			
			// If not exceeded, consume one token for this request
			if (!$exceeded) {
				$bucket['tokens']--;
			}
			
			// Store updated bucket state with extended TTL
			// TTL is 2x window duration to handle clock skew and ensure persistence
			$this->cache->set($cacheKey, $bucket, $this->window * 2);
			
			return [
				// Calculate count as number of tokens consumed (limit - remaining tokens)
				'count'       => $this->limit - floor($bucket['tokens']),
				
				// Whether the request exceeded the rate limit
				'exceeded'    => $exceeded,
				
				// When the bucket will have at least 1 token again
				// If not exceeded, reset time is immediate (0 seconds from now)
				'reset_time'  => $currentTime + ($exceeded ? ceil((1 - $bucket['tokens']) / $refillRate) : 0),
				
				// How long client should wait before retrying
				// Calculate time needed to accumulate 1 token based on refill rate
				'retry_after' => $exceeded ? ceil((1 - $bucket['tokens']) / $refillRate) : 0
			];
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
		 * @param MethodContext $context The request context containing request and routing info
		 * @return string The generated cache key for rate limiting
		 */
		private function generateKey(MethodContext $context): string {
			// Fetch the request from the context
			$request = $context->getRequest();
			
			// Base prefix for all rate limit cache keys
			// This helps organize cache entries and avoid conflicts with other cached data
			$baseKey = 'rate_limit';
			
			// Determine the identifier based on the configured scope
			// Each scope provides different granularity for rate limiting
			$rawIdentifier = match ($this->scope) {
				// Rate limit per IP address - useful for preventing abuse from single sources
				'ip' => $request->getClientIp(),
				
				// Rate limit per authenticated user - allows different limits for different users
				'user' => $this->getUserIdentifier($request),
				
				// Rate limit per API key - useful for API quotas and partner management
				'api_key' => $request->headers->get('X-API-Key', 'anonymous'),
				
				// Global rate limit - applies to all requests regardless of source
				'global' => 'global',
				
				// Custom identifier - allows for flexible rate limiting strategies
				'custom' => $this->identifier,
				
				// Default value (will never occur, but to keep phpstan happy)
				default => new \Exception("Invalid scope")
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
		 * @param $request
		 * @return string
		 */
		protected function getUserIdentifier(Request $request): string {
			// Default implementation: check for user_id in session
			$session = $request->getSession();
			
			if ($session->has('user_id')) {
				return 'user_' . $session->get('user_id');
			}
			
			// Fallback to IP for unauthenticated requests
			return 'ip_' . ($request->getClientIp() ?? 'unknown');
		}
		
		/**
		 * Create appropriate rate limit exceeded response
		 * @param Request $request
		 * @param array $result
		 * @return Response
		 */
		private function createRateLimitResponse(Request $request, array $result): Response {
			$headers = [
				"{$this->headerPrefix}-Limit"     => $this->limit,
				"{$this->headerPrefix}-Remaining" => 0,
				"{$this->headerPrefix}-Reset"     => $result['reset_time'],
				'Retry-After'                     => $result['retry_after']
			];
			
			// Return JSON for API requests, HTML for web requests
			if ($this->isApiRequest($request)) {
				return new JsonResponse([
					'error'       => 'Rate limit exceeded',
					'message'     => "Too many requests. Limit: {$this->limit} per {$this->window} seconds.",
					'retry_after' => $result['retry_after']
				], 429, $headers);
			}
			
			// For web requests, return a simple HTML response
			$html = "
<!DOCTYPE html>
<html lang=\"eng\">
<head><title>Rate Limit Exceeded</title></head>
<body>
    <h1>Too Many Requests</h1>
    <p>You have exceeded the rate limit of {$this->limit} requests per {$this->window} seconds.</p>
    <p>Please try again in {$result['retry_after']} seconds.</p>
</body>
</html>";
			
			return new Response($html, 429, $headers);
		}
		
		/**
		 * Determine if this is an API request
		 * @param Request $request
		 * @return bool
		 */
		private function isApiRequest(Request $request): bool {
			return
				$request->headers->get('Accept') === 'application/json' ||
				str_starts_with($request->getPathInfo(), '/api/') ||
				$request->headers->has('X-API-Key');
		}
	}