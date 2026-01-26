<?php
	
	namespace Quellabs\Canvas\Translation;
	
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Quellabs\Support\ComposerUtils;
	use Quellabs\Support\StringInflector;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * AOP aspect that handles translation loading and locale determination
	 *
	 * Automatically loads translations before controller method execution and makes them
	 * available via request attributes. Supports domain-based translation files with
	 * fallback to default locale.
	 *
	 * Expected translation file structure:
	 * - translations/{locale}/{domain}.php
	 * - Each file returns an associative array of key => translation pairs
	 *
	 * Sets request attributes:
	 * - 'translations': array of loaded translations
	 * - 'locale': determined locale string
	 */
	class TranslationAspect implements BeforeAspectInterface {
		
		/** Translation domain (e.g., "admin", "user") - empty means derive from controller name */
		private string $domain = '';
		
		/** Fallback locale when requested locale is unavailable or invalid */
		private string $defaultLocale = 'en';
		
		/** Whitelist of supported locale codes - only these locales will be accepted */
		private array $availableLocales = ['en', 'nl'];
		
		/** Cache to prevent re-loading same translation files within request */
		private array $loadedTranslations = [];
		
		/**
		 * Construct a new TranslationAspect instance
		 * @param string $domain Translation domain - empty to derive from controller class name (AdminController -> "admin")
		 * @param string $defaultLocale Fallback locale when requested locale is unavailable or invalid
		 * @param array $availableLocales Whitelist of supported locale codes
		 */
		public function __construct(
			string $domain = '',
			string $defaultLocale = 'en',
			array $availableLocales = ['en', 'nl']
		) {
			$this->domain = $domain;
			$this->defaultLocale = $defaultLocale;
			$this->availableLocales = $availableLocales;
		}
		
		/**
		 * Executes before controller method - loads translations and sets request attributes
		 * @param MethodContextInterface $context The method execution context containing request and controller info
		 * @return Response|null Always returns null to allow controller execution to continue
		 */
		public function before(MethodContextInterface $context): ?Response {
			// Use configured domain or derive from controller class name
			$domain = $this->domain ?: $this->deriveFromController($context);
			
			// Determine locale from request (query, session, cookie, header, or default)
			$locale = $this->determineLocale($context->getRequest());
			
			// Load translation file for domain and locale (with fallback to default locale)
			$translations = $this->loadTranslations($domain, $locale);
			
			// Store both translations and locale in request attributes for controller access
			$context->getRequest()->attributes->set('translations', $translations);
			$context->getRequest()->attributes->set('locale', $locale);
			
			// Return null to allow normal controller execution
			return null;
		}
		
		/**
		 * Determine the locale from request with fallback chain
		 *
		 * Priority order:
		 * 1. Query parameter (locale) - explicit user choice for current request
		 * 2. Session - persisted user preference across requests
		 * 3. Cookie - fallback for sessionless persistence
		 * 4. Accept-Language header - browser/client preference (via Symfony's getPreferredLanguage)
		 * 5. Default locale - guaranteed fallback
		 *
		 * Only returns locales present in availableLocales whitelist
		 *
		 * @param Request $request The current HTTP request
		 * @return string Determined locale code (always valid and in availableLocales)
		 */
		private function determineLocale(Request $request): string {
			$sources = [
				fn() => $request->query->get('locale'),
				fn() => $request->hasSession() ? $request->getSession()->get('locale') : null,
				fn() => $request->cookies->get('locale'),
				fn() => $request->getPreferredLanguage($this->availableLocales),
			];
			
			foreach ($sources as $source) {
				$locale = $source();
				
				if ($locale && $this->isValidLocale($locale)) {
					return $locale;
				}
			}
			
			return $this->defaultLocale;
		}
		
		/**
		 * Load translations for the given domain and locale
		 *
		 * Implements two-level fallback:
		 * 1. Try requested locale
		 * 2. If file doesn't exist and locale != default, try default locale
		 *
		 * Caches loaded translations to prevent redundant file I/O within same request
		 *
		 * @param string $domain Translation domain (e.g., "admin", "user")
		 * @param string $locale Locale code (e.g., "en", "nl")
		 * @return array Translation key-value pairs (empty array if no files found)
		 */
		private function loadTranslations(string $domain, string $locale): array {
			// Determine cache key
			$cacheKey = "{$domain}.{$locale}";
			
			// Return cached translations if already loaded in this request
			if (isset($this->loadedTranslations[$cacheKey])) {
				return $this->loadedTranslations[$cacheKey];
			}
			
			// Try to load the requested locale
			$filePath = $this->getTranslationFilePath($domain, $locale);
			
			// Cache and return translations for requested locale
			if (file_exists($filePath)) {
				return $this->loadedTranslations[$cacheKey] = $this->loadTranslationFile($filePath);
			}
			
			// Requested locale file not found - try fallback to default locale
			if ($locale !== $this->defaultLocale) {
				// Try to load the default locale
				$fallbackPath = $this->getTranslationFilePath($domain, $this->defaultLocale);
				
				// Cache and return translations from default locale
				if (file_exists($fallbackPath)) {
					return $this->loadedTranslations[$cacheKey] = $this->loadTranslationFile($fallbackPath);
				}
			}
			
			// No translation files found - cache and return empty array
			return $this->loadedTranslations[$cacheKey] = [];
		}
		
		/**
		 * Get the file path for a translation file
		 *
		 * Path structure: {project_root}/translations/{locale}/{domain}.php
		 * Example: /var/www/translations/nl/admin.php
		 *
		 * @param string $domain Translation domain (e.g., "admin")
		 * @param string $locale Locale code (e.g., "nl")
		 * @return string Absolute path to translation file
		 */
		private function getTranslationFilePath(string $domain, string $locale): string {
			return ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR
				. 'translations' . DIRECTORY_SEPARATOR
				. $locale . DIRECTORY_SEPARATOR
				. $domain . '.php';
		}
		
		/**
		 * Load and validate a translation file
		 *
		 * Expected file format:
		 * <?php
		 * return [
		 *     'key' => 'translation',
		 *     'another.key' => 'Another translation',
		 * ];
		 *
		 * @param string $filePath Absolute path to translation file
		 * @return array Translation key-value pairs
		 * @throws \RuntimeException If file doesn't return an array
		 */
		private function loadTranslationFile(string $filePath): array {
			$translations = require $filePath;
			
			if (!is_array($translations)) {
				throw new \RuntimeException(
					"Translation file '{$filePath}' must return an array"
				);
			}
			
			return $translations;
		}
		
		/**
		 * Check if a locale is in the list of available locales
		 * Uses strict comparison to prevent type juggling attacks
		 * @param string $locale Locale code to validate
		 * @return bool True if locale is in availableLocales, false otherwise
		 */
		private function isValidLocale(string $locale): bool {
			return in_array($locale, $this->availableLocales, true);
		}
		
		/**
		 * Derive domain name from controller class name
		 *
		 * Transformation:
		 * - App\Controllers\AdminController -> "admin"
		 * - App\Controllers\UserProfileController -> "user_profile"
		 * - App\Controllers\APIController -> "api"
		 *
		 * Strips namespace and "Controller" suffix, converts to snake_case
		 *
		 * @param MethodContextInterface $context The method execution context
		 * @return string Derived domain name (snake_case, no "Controller" suffix)
		 * @throws \RuntimeException If controller class name is just "Controller" with no prefix
		 */
		private function deriveFromController(MethodContextInterface $context): string {
			// Get fully qualified class name
			$className = get_class($context->getClass());
			
			// Extract class name from namespace (App\Controllers\AdminController -> AdminController)
			$parts = explode('\\', $className);
			$shortName = end($parts);
			
			// Remove "Controller" suffix (AdminController -> Admin)
			$withoutSuffix = str_replace('Controller', '', $shortName);
			
			// Validate that we have something left after removing suffix
			if ($withoutSuffix === '') {
				throw new \RuntimeException(
					"Cannot derive domain from controller '{$className}' - class name cannot be just 'Controller'"
				);
			}
			
			// Convert to snake_case (UserProfile -> user_profile)
			return StringInflector::snakeCase($withoutSuffix);
		}
	}