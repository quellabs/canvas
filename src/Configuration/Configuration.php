<?php
	
	namespace Quellabs\Canvas\Configuration;
	
	/**
	 * Configuration management class for handling application settings
	 *
	 * This class provides a centralized way to manage configuration data with
	 * support for type casting, default values, and dynamic configuration updates.
	 */
	class Configuration {

		/** @var array The internal configuration storage array */
		private array $config;
		
		/**
		 * Initialize the configuration with optional initial data
		 * @param array $config Initial configuration array (default: empty array)
		 */
		public function __construct(array $config = []) {
			$this->config = $config;
		}
		
		/**
		 * Get the entire configuration array
		 * @return array Complete configuration data
		 */
		public function all(): array {
			return $this->config;
		}
		
		/**
		 * Check if a configuration key exists
		 * @param string $key The configuration key to check
		 * @return bool True if key exists, false otherwise
		 */
		public function has(string $key): bool {
			return array_key_exists($key, $this->config);
		}
		
		/**
		 * Get a specific configuration value
		 * @param string $key The configuration key to retrieve
		 * @param mixed $default Default value if key doesn't exist (default: null)
		 * @return mixed The configuration value or default if not found
		 */
		public function get(string $key, mixed $default = null): mixed {
			return $this->config[$key] ?? $default;
		}
		
		/**
		 * Get configuration value with automatic type casting
		 * @param string $key The configuration key to retrieve
		 * @param string $type Target type for casting (string, int, float, bool, array)
		 * @param mixed $default Default value if key doesn't exist (default: null)
		 * @return mixed The type-cast configuration value or default
		 */
		public function getAs(string $key, string $type, mixed $default = null): mixed {
			$value = $this->get($key, $default);
			
			// Return default immediately if value is null
			if ($value === null) {
				return $default;
			}
			
			// Use match expression for type casting based on requested type
			return match (strtolower($type)) {
				'string' => (string)$value,
				'int', 'integer' => (int)$value,
				'float', 'double' => (float)$value,
				'bool', 'boolean' => $this->castToBoolean($value),
				'array' => $this->castToArray($value),
				default => $value, // Return original value if type not recognized
			};
		}
		
		/**
		 * Get all configuration keys
		 * @return array Array of all configuration keys
		 */
		public function keys(): array {
			return array_keys($this->config);
		}
		
		/**
		 * Set a configuration value
		 * @param string $key The configuration key to set
		 * @param mixed $value The value to assign to the key
		 * @return void
		 */
		public function set(string $key, mixed $value): void {
			$this->config[$key] = $value;
		}
		
		/**
		 * Merge additional configuration data into existing config
		 * Existing keys will be overwritten by new values
		 * @param array $config Configuration array to merge
		 * @return void
		 */
		public function merge(array $config): void {
			$this->config = array_merge($this->config, $config);
		}
		
		/**
		 * Handle boolean casting with support for common string representations
		 * @param mixed $value Value to cast to boolean
		 * @return bool The boolean representation of the value
		 */
		private function castToBoolean(mixed $value): bool {
			// Handle string values with common boolean representations
			if (is_string($value)) {
				return in_array(strtolower($value), ['true', '1', 'yes', 'on']);
			}
			
			// Use PHP's native boolean casting for non-string values
			return (bool)$value;
		}
		
		/**
		 * Handle array casting with support for comma-separated strings
		 *
		 * - Strings are split by comma and trimmed
		 * - Arrays are returned as-is
		 * - Other types are wrapped in an array
		 *
		 * @param mixed $value Value to cast to array
		 * @return array The array representation of the value
		 */
		private function castToArray(mixed $value): array {
			// Convert comma-separated strings to arrays
			if (is_string($value)) {
				return array_map('trim', explode(',', $value));
			}
			
			// Return arrays as-is, wrap other types in array
			return is_array($value) ? $value : [$value];
		}
	}