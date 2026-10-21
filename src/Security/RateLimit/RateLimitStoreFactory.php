<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	use Quellabs\Contracts\Configuration\ConfigurationInterface;

	/**
	 * Builds the configured RateLimitStoreInterface from config/rate_limit.php,
	 * mirroring the 'default' + 'drivers[name]' shape of config/cache.php.
	 */
	class RateLimitStoreFactory {

		/**
		 * @param ConfigurationInterface $config Parsed config/rate_limit.php
		 * @return RateLimitStoreInterface
		 */
		public static function create(ConfigurationInterface $config): RateLimitStoreInterface {
			$driver = $config->get('driver', 'file');
			$driver = is_string($driver) && $driver !== '' ? $driver : 'file';

			$drivers = $config->get('drivers', []);
			$drivers = is_array($drivers) ? $drivers : [];

			$driverConfig = $drivers[$driver] ?? [];
			$driverConfig = is_array($driverConfig) ? $driverConfig : [];

			$class = $driverConfig['class'] ?? self::defaultClassFor($driver);

			if (!is_string($class) || $class === '' || !class_exists($class)) {
				throw new \InvalidArgumentException("Rate limit store driver '{$driver}' is missing a valid 'class' entry");
			}

			$instance = new $class($driverConfig);

			if (!$instance instanceof RateLimitStoreInterface) {
				throw new \RuntimeException("Rate limit store driver class {$class} must implement RateLimitStoreInterface");
			}

			return $instance;
		}

		/**
		 * Fallback class when config/rate_limit.php omits a driver's 'class' entry entirely
		 * @param string $driver
		 * @return class-string
		 */
		private static function defaultClassFor(string $driver): string {
			return match ($driver) {
				'redis' => RedisRateLimitStore::class,
				'memcached' => MemcachedRateLimitStore::class,
				default => FileRateLimitStore::class,
			};
		}
	}
