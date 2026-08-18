<?php

	namespace Quellabs\Canvas\Routing;

	/**
	 * Shared route-normalization logic for classes that resolve "package::key"
	 * route annotations against config files. Requires the using class to expose
	 * a `Kernel $kernel` property.
	 */
	trait NormalizesRoutes {

		/**
		 * Normalizes a route string, resolving config file references if present.
		 * Config references use the format "filename::key" (e.g. "mollie::redirectUrl"),
		 * which is resolved by loading the corresponding config file and looking up the key.
		 * Plain route strings (e.g. "/payment/return") are returned as-is.
		 * @param string $route The route string to normalize, either a plain path or a config reference
		 * @param string|null $default Fallback value if the config key is not found
		 * @return string The resolved route path
		 * @throws \RuntimeException If the config key is not found and no default is provided
		 */
		protected function normalizeRoute(string $route, ?string $default = null): string {
			// Plain route path — nothing to resolve
			if (!str_contains($route, "::")) {
				return $route;
			}

			// Split "filename::key" into its two components
			$parts = explode("::", $route, 2);
			$file  = $parts[0];
			$key   = $parts[1];

			// Load the config file and look up the key, falling back to $default if absent
			$result = $this->kernel->loadConfigFile("{$file}.php")->get($key, $default);

			// No value and no default — the annotation references a key that doesn't exist
			if ($result === null) {
				throw new \RuntimeException("Couldn't load route '{$key}' from config file '{$file}'.");
			}

			// Config values may legitimately be full URLs (e.g. webhook URLs sent to a
			// remote payment provider), so strip scheme/host the same way Route::getRoute()
			// does for a literal URL annotation, ensuring only the path is registered.
			if (str_starts_with($result, 'http://') || str_starts_with($result, 'https://')) {
				$path = parse_url($result, PHP_URL_PATH);

				if ($path !== null && $path !== false) {
					return $path;
				}
			}

			return $result;
		}
	}
