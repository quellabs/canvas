<?php
	
	namespace Quellabs\Canvas\Cache;
	
	use Quellabs\Canvas\AOP\Contracts\AroundAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Quellabs\Contracts\Cache\CacheInterface;
	use Quellabs\DependencyInjection\Container;
	use Psr\Log\LoggerInterface;
	use Psr\Log\NullLogger;
	
	/**
	 * Caches the return value of controller methods using configurable cache keys and TTL.
	 *
	 * This aspect provides method-level caching with the following features:
	 * - Collision-resistant cache keys using SHA-256
	 * - Configurable TTL and cache contexts
	 * - Graceful fallback when caching fails
	 * - Cache stampede protection via probabilistic early expiration
	 * - Proper structured logging with context
	 *
	 * The cache key is constructed by combining the method signature with method arguments.
	 *
	 * Example:
	 * - Method: ProductController::getProduct($id)
	 * - Arguments: [123]
	 * - Final cache key: "product_controller.get_product.arg0:123"
	 *
	 * Thread-safety is provided by the underlying CacheInterface implementation.
	 * Most cache drivers (Redis, Memcached, File with locks) provide atomic operations
	 * to prevent race conditions during cache reads/writes.
	 *
	 * Cache Stampede Protection:
	 * When beta > 0, uses XFetch algorithm to probabilistically recompute values before
	 * expiration. This prevents multiple requests from simultaneously recomputing expensive
	 * operations when the cache expires under high load.
	 */
	class CacheAspect implements AroundAspectInterface {
		
		/** @var Container|null Dependency Injector */
		private ?Container $di;
		
		/** @var LoggerInterface Logger instance */
		private LoggerInterface $logger;
		
		/** @var string|null The driver we want to use (file, memcached, redis) */
		private ?string $driver;
		
		/** @var string|null Cache key template */
		private ?string $key;
		
		/** @var string Context/namespace */
		private string $namespace;
		
		/** @var int Time to live in seconds */
		private int $ttl;
		
		/** @var bool Whether to gracefully handle cache failures */
		private bool $gracefulFallback;
		
		/** @var float Beta value for probabilistic early expiration (0.0-1.0) */
		private float $beta;
		
		/** @var array All passed parameters from the InterceptWith */
		private array $allParameters;
		
		/** @var int Maximum cache key length before hashing */
		private const int MAX_KEY_LENGTH = 200;
		
		/** @var int Maximum readable prefix length when hashing long keys */
		private const int HASH_PREFIX_LENGTH = 80;
		
		/** @var int Hash digest length for truncated keys */
		private const int HASH_DIGEST_LENGTH = 32;
		
		/**
		 * CacheAspect constructor
		 * @param Container|null $di Dependency Injector
		 * @param LoggerInterface|null $logger PSR-3 logger for cache operations (uses NullLogger if not provided)
		 * @param string|null $driver The driver we want to use (file, memcached, redis) - null uses default
		 * @param string|null $key Cache key template (null = auto-generate from method context) - supports placeholders
		 * @param int $ttl Time to live in seconds (0 = never expires, default 3600 = 1 hour)
		 * @param string $namespace Cache group for namespacing (prevents key collisions between features)
		 * @param bool $gracefulFallback Whether to execute method if caching fails (recommended: true)
		 * @param float $beta Probabilistic early expiration factor (0.0 = disabled, 0.5-1.0 = recommended, 1.0 = aggressive)
		 * @param array $__all__ Special 'magic' variable that receives all InterceptWith parameters from DI
		 */
		public function __construct(
			Container $di = null,
			?LoggerInterface $logger = null,
			?string   $driver = null,
			?string   $key = null,
			int       $ttl = 3600,
			string    $namespace = 'default',
			bool      $gracefulFallback = true,
			float     $beta = 0.0,
			array     $__all__ = []
		) {
			$this->allParameters = $__all__;
			$this->di = $di;
			$this->logger = $logger ?? new NullLogger();
			$this->driver = $driver;
			$this->key = $key;
			$this->ttl = max(0, $ttl);
			$this->namespace = $namespace;
			$this->gracefulFallback = $gracefulFallback;
			$this->beta = max(0.0, min(1.0, $beta));
		}
		
		/**
		 * Cache the method execution result
		 *
		 * Execution flow:
		 * 1. Generate cache key from method signature + arguments
		 * 2. Check if probabilistic early expiration should trigger
		 * 3. On cache hit: return cached value
		 * 4. On cache miss: execute method, cache result, return
		 * 5. On error: log details and either fallback or throw
		 *
		 * @param MethodContextInterface $context Method execution context
		 * @param callable $proceed Callback to execute the original method
		 * @return mixed Cached or computed result
		 * @throws \RuntimeException If caching fails and gracefulFallback is disabled
		 */
		public function around(MethodContextInterface $context, callable $proceed): mixed {
			$cacheKey = null;
			
			try {
				// Initialize cache with concurrency protection
				// The cache interface handles thread-safety and race conditions
				$cache = $this->di->get(CacheInterface::class, [
					'driver'    => $this->driver,
					'namespace' => $this->namespace,
					'config'    => $this->allParameters
				]);
				
				// Resolve a dynamic cache key
				// Combines method signature with serialized arguments
				$cacheKey = $this->resolveCacheKey($context);
				
				// Check for probabilistic early expiration to prevent stampede
				// When beta > 0, occasionally refreshes cache before expiration
				// This prevents multiple requests from simultaneously recomputing on expiry
				
				if ($this->beta > 0.0 && $this->shouldRecomputeEarly($cache, $cacheKey)) {
					// Recompute the value
					$computeStart = microtime(true);
					$result = $proceed();
					$computeTime = microtime(true) - $computeStart;
					
					// Store with fresh TTL
					// This atomic operation prevents other requests from also recomputing
					$cache->put($cacheKey, $result, $this->ttl);
					
					// Log early refresh (useful for monitoring stampede protection effectiveness)
					$this->logger->info('Cache refreshed early (stampede protection)', [
						'cache_key' => $cacheKey,
						'compute_time_ms' => round($computeTime * 1000, 2),
						'beta' => $this->beta
					]);
					
					return $result;
				}
				
				// Use cache remember pattern with stampede protection
				// remember() is atomic: only one request computes on cache miss
				return $cache->remember($cacheKey, $this->ttl, function () use ($proceed, $cacheKey) {
					$computeStart = microtime(true);
					$result = $proceed();
					$computeTime = microtime(true) - $computeStart;
					
					// Only log cache misses (cache hits are silent for performance)
					$this->logger->info('Cache miss - computed value', [
						'cache_key' => $cacheKey,
						'compute_time_ms' => round($computeTime * 1000, 2)
					]);
					
					return $result;
				});
				
			} catch (\Exception $e) {
				// Log cache failure with full context for debugging
				$this->logger->error('Cache aspect failed', [
					'cache_key' => $cacheKey,
					'namespace' => $this->namespace,
					'method' => $context->getMethodName(),
					'class' => get_class($context->getClass()),
					'error' => $e->getMessage(),
					'error_class' => get_class($e),
					'graceful_fallback' => $this->gracefulFallback
				]);
				
				// Handle cache failure based on configuration
				if ($this->gracefulFallback) {
					// Graceful degradation: execute method without caching
					// Prevents cascade failures when cache is unavailable
					return $proceed();
				}
				
				// Strict mode: propagate error to caller
				throw new \RuntimeException(
					sprintf(
						'Cache aspect failed for %s::%s: %s',
						get_class($context->getClass()),
						$context->getMethodName(),
						$e->getMessage()
					),
					0,
					$e
				);
			}
		}
		
		/**
		 * Resolve the cache key from method context and arguments
		 *
		 * Key generation strategy:
		 * 1. Use explicit key if provided, otherwise auto-generate from method
		 * 2. Append serialized arguments for differentiation
		 * 3. Normalize to ensure cache system compatibility
		 *
		 * Example outputs:
		 * - "product_controller.get_product.arg0:123"
		 * - "user_controller.find_by_email.arg0:user-example.com"
		 * - "custom_key.arg0:foo_arg1:bar"
		 *
		 * @param MethodContextInterface $context
		 * @return string
		 */
		private function resolveCacheKey(MethodContextInterface $context): string {
			// Generate key from method context if not provided
			if ($this->key !== null) {
				$methodKey = $this->key;
			} else {
				$methodKey = $this->generateMethodKey($context);
			}
			
			// Use method arguments for cache differentiation
			// Same method with different arguments gets different cache entries
			$argumentsKey = $this->generateArgumentsKey($context->getArguments());
			$cacheKey = $methodKey . '.' . $argumentsKey;
			
			// Normalize and return the generated key
			// Ensures compatibility with cache system constraints
			return $this->normalizeCacheKey($cacheKey);
		}
		
		/**
		 * Generate a cache key based on method context
		 * @param MethodContextInterface $context Method execution context
		 * @return string Generated cache key (e.g., "product_controller.get_product")
		 */
		private function generateMethodKey(MethodContextInterface $context): string {
			// Get class and method information
			$target = $context->getClass();
			$className = get_class($target);
			$methodName = $context->getMethodName();
			
			// Extract short class name
			$shortClassName = substr(strrchr($className, '\\'), 1) ?: $className;
			
			// Convert class name to snake_case for readability
			$classIdentifier = strtolower(preg_replace('/([a-z])([A-Z])/', '$1_$2', $shortClassName));
			
			// Create the method-specific key
			return "{$classIdentifier}.{$methodName}";
		}
		
		/**
		 * Generate a cache key component from method arguments
		 * @param array $arguments Method arguments
		 * @return string Sanitized arguments key
		 */
		private function generateArgumentsKey(array $arguments): string {
			// If no argument, return placeholder
			if (empty($arguments)) {
				return 'no_args';
			}
			
			// Convert arguments to a consistent string representation
			$serialized = $this->serializeArguments($arguments);
			
			// Use SHA-256 for collision resistance instead of CRC32
			// Keep a readable prefix for debugging
			if (strlen($serialized) > 50) {
				$prefix = substr($serialized, 0, 30);
				$hash = hash('sha256', $serialized);

				// Use first 16 chars of SHA-256 (64-bit collision resistance)
				return $this->sanitizeValue($prefix) . '_' . substr($hash, 0, 16);
			}
			
			return $this->sanitizeValue($serialized);
		}
		
		/**
		 * Serialize method arguments to a consistent string format
		 * @param array $arguments Method arguments
		 * @return string Serialized arguments
		 */
		private function serializeArguments(array $arguments): string {
			$parts = [];
			
			foreach ($arguments as $index => $arg) {
				$parts[] = $this->serializeArgument($arg, "arg{$index}");
			}
			
			return implode('_', $parts);
		}
		
		/**
		 * Serialize a single argument to string format
		 *
		 * Handles different types with appropriate serialization:
		 * - Scalars: direct conversion
		 * - Arrays: JSON + SHA-256 hash
		 * - Objects: ID/toString/toArray/properties + hash
		 * - Resources/Closures: throw exception (not cacheable)
		 *
		 * Uses SHA-256 for complex types to ensure collision resistance.
		 * CRC32 would create 4-billion keyspace, causing frequent collisions.
		 *
		 * @param mixed $argument The argument to serialize
		 * @param string $prefix Prefix for the argument (for readability)
		 * @return string Serialized argument
		 * @throws \InvalidArgumentException|\JsonException If argument contains non-serializable data
		 */
		private function serializeArgument(mixed $argument, string $prefix): string {
			// Null values - explicit representation
			if ($argument === null) {
				return "{$prefix}:null";
			}
			
			// Boolean values - explicit true/false strings
			if (is_bool($argument)) {
				return "{$prefix}:" . ($argument ? 'true' : 'false');
			}
			
			// Scalar values (string, int, float) - direct conversion
			if (is_scalar($argument)) {
				return "{$prefix}:" . (string)$argument;
			}
			
			// Arrays - validate then hash with JSON for consistency
			if (is_array($argument)) {
				// Validate array is serializable (no resources/closures)
				$this->validateSerializable($argument, $prefix);
				
				// For arrays, create a hash to keep keys manageable
				// Use JSON for consistent serialization across runs
				// json_encode produces deterministic output for same data
				$json = json_encode($argument, JSON_THROW_ON_ERROR);
				return "{$prefix}:array_" . hash('sha256', $json);
			}
			
			// Objects
			if (is_object($argument)) {
				// Validate object is serializable
				$this->validateSerializable($argument, $prefix);
				
				$className = get_class($argument);
				$shortName = substr(strrchr($className, '\\'), 1) ?: $className;
				
				// Strategy 1: Try to get a meaningful identifier from the object
				// Best for entities with database IDs
				if (method_exists($argument, 'getId')) {
					$id = $argument->getId();
					// Ensure ID is scalar (not another object)
					
					if (!is_scalar($id)) {
						throw new \InvalidArgumentException(
							"Object {$className}::getId() returned non-scalar value in {$prefix}"
						);
					}
					return "{$prefix}:{$shortName}:" . $id;
				}
				
				// Strategy 2: Use __toString if available
				// Good for value objects with string representations
				if (method_exists($argument, '__toString')) {
					return "{$prefix}:{$shortName}:" . (string)$argument;
				}
				
				// Strategy 3: Use toArray if available
				// Good for objects that can serialize themselves
				if (method_exists($argument, 'toArray')) {
					$array = $argument->toArray();
					$this->validateSerializable($array, $prefix);
					$json = json_encode($array, JSON_THROW_ON_ERROR);
					return "{$prefix}:{$shortName}:" . hash('sha256', $json);
				}
				
				// Strategy 4: For objects implementing JsonSerializable
				
				if ($argument instanceof \JsonSerializable) {
					$json = json_encode($argument, JSON_THROW_ON_ERROR);
					return "{$prefix}:{$shortName}:" . hash('sha256', $json);
				}
				
				// Strategy 5: Last resort - serialize object properties via reflection
				// This is slower but handles arbitrary objects
				try {
					$reflection = new \ReflectionClass($argument);
					$properties = [];
					
					foreach ($reflection->getProperties() as $property) {
						$property->setAccessible(true);
						$value = $property->getValue($argument);
						
						// Skip non-serializable properties
						// Resources and closures can't be cached
						if (is_resource($value) || $value instanceof \Closure) {
							continue;
						}
						
						$properties[$property->getName()] = $value;
					}
					
					$json = json_encode($properties, JSON_THROW_ON_ERROR);
					return "{$prefix}:{$shortName}:" . hash('sha256', $json);
					
				} catch (\Exception $e) {
					throw new \InvalidArgumentException(
						"Cannot serialize object of class {$className} in {$prefix}: {$e->getMessage()}"
					);
				}
			}
			
			if (is_resource($argument)) {
				throw new \InvalidArgumentException(
					"Cannot cache methods with resource arguments in {$prefix}"
				);
			}
			
			// Fallback for other types
			throw new \InvalidArgumentException(
				"Cannot serialize argument of type " . gettype($argument) . " in {$prefix}"
			);
		}
		
		/**
		 * Validate that a value is serializable (no resources or closures)
		 *
		 * This is critical for cache safety - we cannot cache:
		 * - Resources (file handles, database connections, sockets)
		 * - Closures (functions, anonymous functions)
		 * - Objects containing the above in their properties
		 *
		 * Recursively validates arrays and object properties to catch
		 * deeply nested non-serializable values.
		 *
		 * @param mixed $value Value to validate
		 * @param string $context Context for error messages (e.g., "arg0", "arg1[key]")
		 * @throws \InvalidArgumentException If value contains non-serializable data
		 */
		private function validateSerializable(mixed $value, string $context): void {
			// Resources cannot be serialized (file handles, DB connections, etc.)
			if (is_resource($value)) {
				throw new \InvalidArgumentException(
					"Cannot cache methods with resource arguments in {$context}"
				);
			}
			
			// Closures cannot be serialized (functions, callbacks)
			if ($value instanceof \Closure) {
				throw new \InvalidArgumentException(
					"Cannot cache methods with Closure arguments in {$context}"
				);
			}
			
			// Recursively validate arrays
			if (is_array($value)) {
				foreach ($value as $key => $item) {
					$this->validateSerializable($item, "{$context}[{$key}]");
				}
			}
			
			// Validate object properties don't contain resources
			if (is_object($value)) {
				// Check for common non-serializable object types
				if ($value instanceof \Closure) {
					throw new \InvalidArgumentException(
						"Cannot cache methods with Closure arguments in {$context}"
					);
				}
				
				// Resources wrapped in objects
				// Check object properties via reflection
				try {
					$reflection = new \ReflectionClass($value);
					foreach ($reflection->getProperties() as $property) {
						$property->setAccessible(true);
						$propValue = $property->getValue($value);
						
						if (is_resource($propValue)) {
							throw new \InvalidArgumentException(
								"Cannot cache methods with resource properties in {$context}::" . $property->getName()
							);
						}
					}
				} catch (\ReflectionException $e) {
					// If we can't reflect, we can't validate - let it through
					// Some internal PHP classes don't support reflection
				}
			}
		}
		
		/**
		 * Sanitize a value for use in cache keys
		 * @param mixed $value Value to sanitize
		 * @return string Sanitized value (safe for cache keys)
		 */
		private function sanitizeValue(mixed $value): string {
			// Convert to string and limit length
			$stringValue = substr((string)$value, 0, 100);
			
			// Replace problematic characters with safe alternatives
			// Only allow alphanumeric, dash, underscore, and period
			$sanitized = preg_replace('/[^a-zA-Z0-9\-_.]/', '-', $stringValue);
			
			// Remove consecutive dashes and trim
			$sanitized = preg_replace('/-+/', '-', $sanitized);
			$sanitized = trim($sanitized, '-');
			
			// Ensure we have a non-empty result
			return $sanitized ?: 'empty';
		}
		
		/**
		 * Normalize the cache key
		 * @param string $key Cache key to validate
		 * @return string Validated cache key
		 */
		private function normalizeCacheKey(string $key): string {
			// Remove any remaining unreplaced placeholders
			// These might come from custom key templates
			$key = preg_replace('/\{[^}]+}/', 'missing', $key);
			
			// Ensure key isn't too long (many cache systems have 250 char limits)
			// If too long, create a hybrid: readable prefix + hash suffix
			if (strlen($key) > self::MAX_KEY_LENGTH) {
				// Hash the key if it's too long, but preserve some readable portion
				$prefix = substr($key, 0, self::HASH_PREFIX_LENGTH);
				$hash = hash('sha256', $key);
				$key = $prefix . '.' . substr($hash, 0, self::HASH_DIGEST_LENGTH);
			}
			
			// Final cleanup - remove leading/trailing separators
			$key = trim($key, '.-');
			
			// Ensure we have a valid key
			// Should never happen, but provides a safe fallback
			return $key ?: 'default.cache.key';
		}
		
		/**
		 * Determine if cache should be recomputed early to prevent stampede
		 *
		 * Uses the XFetch algorithm with probabilistic early expiration:
		 * P(recompute) = beta * compute_time / remaining_ttl
		 *
		 * This prevents cache stampede by having one request probabilistically
		 * recompute the value before it expires, with higher probability as
		 * expiration approaches.
		 *
		 * How it works:
		 * 1. For a cache entry with 60s TTL and 10s compute time:
		 *    - At t=0 (fresh): P = beta * 10/60 = 0.167 * beta
		 *    - At t=50 (near expiry): P = beta * 10/10 = 1.0 * beta
		 * 2. With beta=1.0, when remaining_ttl equals compute_time,
		 *    we're guaranteed to trigger refresh
		 * 3. With beta=0.5, we trigger more conservatively
		 *
		 * Benefits:
		 * - Prevents thundering herd on expiration
		 * - Expensive operations get refreshed earlier
		 * - Only one request typically wins the race
		 * - Others continue serving slightly stale data
		 *
		 * @param CacheInterface $cache Cache instance
		 * @param string $cacheKey Cache key to check
		 * @return bool True if should recompute early
		 */
		private function shouldRecomputeEarly(CacheInterface $cache, string $cacheKey): bool {
			// Get metadata about cached item if available
			// This requires cache driver to support metadata retrieval
			if (!method_exists($cache, 'getMetadata')) {
				return false;
			}
			
			try {
				$metadata = $cache->getMetadata($cacheKey);
				
				// Need both creation time and TTL to calculate probability
				
				if (!$metadata || !isset($metadata['created_at'], $metadata['ttl'])) {
					return false;
				}
				
				$now = time();
				$createdAt = $metadata['created_at'];
				$ttl = $metadata['ttl'];
				
				// Calculate age and remaining TTL
				$age = $now - $createdAt;
				$remainingTtl = max(1, $ttl - $age); // Avoid division by zero
				
				// If already expired, don't trigger early - let normal flow handle it
				// This prevents double-computation
				if ($remainingTtl <= 0) {
					return false;
				}
				
				// Estimate compute time from last computation if available
				// Otherwise use a conservative estimate of 1 second
				$estimatedComputeTime = $metadata['compute_time'] ?? 1.0;
				
				// XFetch algorithm: P(recompute) = beta * delta / ttl_remaining
				// where delta is the expected computation time
				// As remaining_ttl decreases, probability increases
				$probability = $this->beta * $estimatedComputeTime / $remainingTtl;
				
				// Random dice roll - each request independently decides
				// This ensures eventual recomputation without coordination
				$roll = mt_rand() / mt_getrandmax();
				return $roll < $probability;
				
			} catch (\Exception $e) {
				// If metadata retrieval fails, don't trigger early expiration
				// Fail gracefully and let normal cache flow handle it
				// Log as warning since stampede protection won't work
				$this->logger->warning('Cache metadata unavailable - stampede protection disabled', [
					'cache_key' => $cacheKey,
					'error' => $e->getMessage()
				]);
				
				return false;
			}
		}
	}