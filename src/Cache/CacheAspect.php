<?php
	
	namespace Quellabs\Canvas\Cache;
	
	use Quellabs\Canvas\AOP\Contracts\AroundAspectInterfaceInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Quellabs\Contracts\Cache\CacheInterface;
	use Quellabs\DependencyInjection\Container;
	
	/**
	 * Caches the return value of controller methods using configurable cache keys and TTL.
	 *
	 * This aspect provides method-level caching with the following features:
	 * - Cache keys based on method context and arguments
	 * - Configurable TTL and cache contexts
	 * - Graceful fallback when caching fails
	 * - Thread-safe caching using FileCache with concurrency protection
	 *
	 * The cache key is constructed by combining the method signature with method arguments.
	 *
	 * Example:
	 * - Method: ProductController::getProduct($id)
	 * - Arguments: [123]
	 * - Final cache key: "product_controller.get_product.arg0:123"
	 */
	class CacheAspect implements AroundAspectInterfaceInterface {
		
		/** @var Container|null Dependency Injector */
		private ?Container $di;
		
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
		
		/** @var array All passed parameters from the InterceptWith */
		private array $allParameters;
		
		/**
		 * CacheAspect constructor
		 * @param Container|null $di Dependency Injector
		 * @param string|null $driver The driver we want to use (file, memcached, redis)
		 * @param string|null $key Cache key template (null = auto-generate from method context)
		 * @param int $ttl Time to live in seconds (0 = never expires)
		 * @param string $namespace Cache group for namespacing
		 * @param bool $gracefulFallback Whether to execute method if caching fails
		 * @param array $__all__ Special 'magic' variable that receives all InterceptWith parameters from DI
		 */
		public function __construct(
			Container $di = null,
			?string   $driver = null,
			?string   $key = null,
			int       $ttl = 3600,
			string    $namespace = 'default',
			bool      $gracefulFallback = true,
			array     $__all__ = []
		) {
			$this->allParameters = $__all__;
			$this->di = $di;
			$this->driver = $driver;
			$this->key = $key;
			$this->ttl = max(0, $ttl); // Ensure non-negative TTL
			$this->namespace = $namespace;
			$this->gracefulFallback = $gracefulFallback;
		}
		
		/**
		 * Cache the method execution result
		 * @param MethodContextInterface $context Method execution context
		 * @param callable $proceed Callback to execute the original method
		 * @return mixed Cached or computed result
		 * @throws \RuntimeException If caching fails and gracefulFallback is disabled
		 */
		public function around(MethodContextInterface $context, callable $proceed): mixed {
			try {
				// Initialize cache with concurrency protection
				$cache = $this->di->get(CacheInterface::class, [
					'driver'    => $this->driver,
					'namespace' => $this->namespace,
					'config'    => $this->allParameters
				]);
				
				// Resolve a dynamic cache key
				$cacheKey = $this->resolveCacheKey($context);
				
				// Use cache remember pattern for atomic cache-aside operations
				return $cache->remember($cacheKey, $this->ttl, function () use ($proceed) {
					return $proceed();
				});
				
			} catch (\Exception $e) {
				// Handle cache failure based on configuration
				if ($this->gracefulFallback) {
					// Log the error
					error_log($e->getMessage());
					
					// Execute original method without caching
					return $proceed();
				}
				
				// Re-throw exception if graceful fallback is disabled
				throw new \RuntimeException('Cache aspect failed: ' . $e->getMessage(), 0, $e);
			}
		}
		
		/**
		 * Resolve the cache key from method context and arguments
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
			$argumentsKey = $this->generateArgumentsKey($context->getArguments());
			$cacheKey = $methodKey . '.' . $argumentsKey;
			
			// Normalize and return the generated key
			return $this->normalizeCacheKey($cacheKey);
		}
		
		/**
		 * Generate a cache key based on method context
		 * @param MethodContextInterface $context Method execution context
		 * @return string Generated cache key
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
			
			// Create a hash for long argument lists to keep keys manageable
			if (strlen($serialized) > 50) {
				return substr($serialized, 0, 30) . '_' . hash('crc32', $serialized);
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
		 * @param mixed $argument The argument to serialize
		 * @param string $prefix Prefix for the argument (for readability)
		 * @return string Serialized argument
		 */
		private function serializeArgument(mixed $argument, string $prefix): string {
			if ($argument === null) {
				return "{$prefix}:null";
			}
			
			if (is_bool($argument)) {
				return "{$prefix}:" . ($argument ? 'true' : 'false');
			}
			
			if (is_scalar($argument)) {
				return "{$prefix}:" . (string)$argument;
			}
			
			if (is_array($argument)) {
				// For arrays, create a hash to keep keys manageable
				return "{$prefix}:array_" . hash('crc32', serialize($argument));
			}
			
			if (is_object($argument)) {
				// For objects, use class name and a hash of properties
				$className = get_class($argument);
				$shortName = substr(strrchr($className, '\\'), 1) ?: $className;
				
				// Try to get a meaningful identifier from the object
				if (method_exists($argument, 'getId')) {
					return "{$prefix}:{$shortName}:" . $argument->getId();
				}
				
				if (method_exists($argument, '__toString')) {
					return "{$prefix}:{$shortName}:" . (string)$argument;
				}
				
				// Fallback to object hash
				return "{$prefix}:{$shortName}:" . hash('crc32', serialize($argument));
			}
			
			// Fallback for other types
			return "{$prefix}:" . hash('crc32', serialize($argument));
		}
		
		/**
		 * Sanitize a value for use in cache keys
		 * @param mixed $value Value to sanitize
		 * @return string Sanitized value
		 */
		private function sanitizeValue(mixed $value): string {
			// Convert to string and limit length
			$stringValue = substr((string)$value, 0, 100);
			
			// Replace problematic characters with safe alternatives
			$sanitized = preg_replace('/[^a-zA-Z0-9\-_.\\/]/', '-', $stringValue);
			
			// Remove consecutive dashes and trim
			$sanitized = preg_replace('/-+/', '-', $sanitized);
			$sanitized = trim($sanitized, '-');
			
			// Ensure we have a non-empty result
			return $sanitized ?: 'empty';
		}
		
		/**
		 * Normalize the cache key
		 *
		 * This method ensures the cache key meets requirements:
		 * - Not too long (cache systems have key length limits)
		 * - Contains only safe characters
		 * - Has a reasonable structure
		 *
		 * @param string $key Cache key to validate
		 * @return string Validated cache key
		 */
		private function normalizeCacheKey(string $key): string {
			// Remove any remaining unreplaced placeholders
			$key = preg_replace('/\{[^}]+}/', 'missing', $key);
			
			// Ensure key isn't too long (many cache systems have 250 char limits)
			if (strlen($key) > 200) {
				// Hash the key if it's too long, but preserve some readable portion
				$prefix = substr($key, 0, 100);
				$hash = hash('sha256', $key);
				$key = $prefix . '.' . substr($hash, 0, 16);
			}
			
			// Final cleanup
			$key = trim($key, '.-');
			
			// Ensure we have a valid key
			return $key ?: 'default.cache.key';
		}
	}