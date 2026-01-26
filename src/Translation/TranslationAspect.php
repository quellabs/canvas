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
	 * - 'translations': array of loaded translations (use this for rendering)
	 * - 'locale': requested/determined locale (use for UI context like date/number formatting)
	 * - 'resolved_locale': actual locale file loaded (use for debugging/logging fallback events)
	 */
	class TranslationAspect implements BeforeAspectInterface {
		
		/** Translation domain (e.g., "admin", "user") - empty means derive from controller name */
		private string $domain;
		
		/** Fallback locale when requested locale is unavailable or invalid */
		private string $defaultLocale;
		
		/** Cache to prevent re-loading same translation files within request */
		private array $loadedTranslations = [];
		
		/** Static cache of available locales per domain (shared across all instances) */
		private static array $availableLocalesByDomain = [];
		
		/**
		 * Constructor
		 * @param string $domain Translation domain - empty to derive from controller class name (AdminController -> "admin")
		 * @param string $defaultLocale Fallback locale when requested locale is unavailable or invalid
		 */
		public function __construct(string $domain = '', string $defaultLocale = 'en') {
			$this->domain = $domain;
			$this->defaultLocale = $defaultLocale;
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
			$requestedLocale = $this->determineLocale($context->getRequest(), $domain);
			
			// Load translation file for domain and locale (with fallback to default locale)
			[$translations, $resolvedLocale] = $this->loadTranslations($domain, $requestedLocale);
			
			// Store translations, requested locale, and resolved locale in request attributes
			$context->getRequest()->attributes->set('translations', $translations);
			$context->getRequest()->attributes->set('locale', $requestedLocale);
			$context->getRequest()->attributes->set('resolved_locale', $resolvedLocale);
			
			// Return null to allow normal controller execution
			return null;
		}
		
		/**
		 * Clear static locale cache
		 * @param string|null $domain Optional domain to clear (null clears all)
		 */
		public static function clearLocaleCache(?string $domain = null): void {
			if ($domain === null) {
				self::$availableLocalesByDomain = [];
			} else {
				unset(self::$availableLocalesByDomain[$domain]);
			}
		}

		/**
		 * Determine the locale from request with fallback chain
		 *
		 * Priority order:
		 * 1. Query parameter (locale) - explicit user choice for current request
		 * 2. Session - persisted user preference across requests
		 * 3. Cookie - fallback for sessionless persistence
		 * 4. Accept-Language header - browser/client preference
		 * 5. Default locale (if translation file exists)
		 * 6. First available locale for domain (if default doesn't exist)
		 * 7. Default locale anyway (logical UI locale, may have no translations)
		 *
		 * All locales from sources 1-4 are validated for:
		 * - Security (alphanumeric + underscore/hyphen only)
		 * - Availability (translation file must exist for domain)
		 *
		 * Final fallback (step 7) returns defaultLocale even without translations.
		 * The 'resolved_locale' attribute indicates which file was actually loaded,
		 * but consumers render from 'translations' array directly (no locale needed).
		 *
		 * @param Request $request The current HTTP request
		 * @param string $domain Translation domain to check filesystem for available locales
		 * @return string Determined locale code (user preference for UI context)
		 */
		private function determineLocale(Request $request, string $domain): string {
			$sources = [
				fn() => $request->query->get('locale'),
				fn() => $request->hasSession() ? $request->getSession()->get('locale') : null,
				fn() => $request->cookies->get('locale'),
				fn() => $this->getPreferredLocaleFromFilesystem($request, $domain),
			];
			
			foreach ($sources as $source) {
				$locale = $source();
				
				if ($locale && $this->isValidLocale($locale) && $this->hasTranslationFile($domain, $locale)) {
					return $locale;
				}
			}
			
			// Check if default locale has translations
			if ($this->hasTranslationFile($domain, $this->defaultLocale)) {
				return $this->defaultLocale;
			}
			
			// Default locale doesn't exist - fallback to first available locale for this domain
			$availableLocales = $this->getAvailableLocalesForDomain($domain);
			
			if (!empty($availableLocales)) {
				return $availableLocales[0];
			}
			
			// No translations exist at all - return default locale anyway
			// (loadTranslations will return empty array)
			return $this->defaultLocale;
		}
		
		/**
		 * Load translations for the given domain and locale
		 *
		 * Implements two-level fallback:
		 * 1. Try requested locale
		 * 2. If file doesn't exist and locale != default, try default locale
		 *
		 * Returns both translations and the actual locale used (may differ from requested)
		 * Caches loaded translations to prevent redundant file I/O within same request
		 *
		 * @param string $domain Translation domain (e.g., "admin", "user")
		 * @param string $locale Requested locale code (e.g., "en", "nl")
		 * @return array [translations array, resolved locale string]
		 */
		private function loadTranslations(string $domain, string $locale): array {
			$cacheKey = "{$domain}.{$locale}";
			
			// Check cache first for requested locale
			if (isset($this->loadedTranslations[$cacheKey])) {
				return [$this->loadedTranslations[$cacheKey], $locale];
			}
			
			// Not in cache - try to load the requested locale file
			$filePath = $this->getTranslationFilePath($domain, $locale);
			
			if (file_exists($filePath)) {
				$this->loadedTranslations[$cacheKey] = $this->loadTranslationFile($filePath);
				return [$this->loadedTranslations[$cacheKey], $locale];
			}
			
			// Requested locale file not found - try fallback to default locale
			if ($locale !== $this->defaultLocale) {
				$fallbackCacheKey = "{$domain}.{$this->defaultLocale}";
				
				// Check cache for default locale
				if (isset($this->loadedTranslations[$fallbackCacheKey])) {
					return [$this->loadedTranslations[$fallbackCacheKey], $this->defaultLocale];
				}
				
				// Not in cache - try to load default locale file
				$fallbackPath = $this->getTranslationFilePath($domain, $this->defaultLocale);
				
				if (file_exists($fallbackPath)) {
					$this->loadedTranslations[$fallbackCacheKey] = $this->loadTranslationFile($fallbackPath);
					return [$this->loadedTranslations[$fallbackCacheKey], $this->defaultLocale];
				}
			}
			
			// No translation files found - cache empty array to avoid repeated disk checks
			$this->loadedTranslations[$cacheKey] = [];
			return [[], $locale]; // Return requested locale even though no translations exist
		}
		
		/**
		 * Get the file path for a translation file
		 *
		 * Path structure: {project_root}/translations/{locale}/{domain}.php
		 * Example: /var/www/project_root/translations/nl/admin.php
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
		 * Check if a locale code is safe to use in filesystem paths
		 *
		 * Validates that locale contains only:
		 * - Letters (a-z, A-Z)
		 * - Digits (0-9)
		 * - Underscores (_)
		 * - Hyphens (-)
		 *
		 * This prevents path traversal attacks while allowing standard locale codes
		 * like "en", "en_US", "pt-BR", "zh-Hans", etc.
		 *
		 * @param string $locale Locale code to validate
		 * @return bool True if locale is safe for filesystem use, false otherwise
		 */
		private function isValidLocale(string $locale): bool {
			// Must be non-empty and contain only safe characters (alphanumeric + _ -)
			return $locale !== '' && preg_match('/^[a-z0-9_-]+$/i', $locale) === 1;
		}
		/**
		 * Get all available locales for a given domain
		 *
		 * Scans the translations directory and returns locales that have
		 * translation files for the specified domain.
		 *
		 * @param string $domain Translation domain
		 * @return array Array of available locale codes
		 */
		private function getAvailableLocalesForDomain(string $domain): array {
			// Check static cache first
			if (isset(self::$availableLocalesByDomain[$domain])) {
				return self::$availableLocalesByDomain[$domain];
			}
			
			$translationsPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . 'translations';
			
			if (!is_dir($translationsPath)) {
				self::$availableLocalesByDomain[$domain] = [];
				return [];
			}
			
			$availableLocales = [];
			$localeDirectories = scandir($translationsPath);
			
			foreach ($localeDirectories as $localeDir) {
				if ($localeDir === '.' || $localeDir === '..') {
					continue;
				}
				
				$localePath = $translationsPath . DIRECTORY_SEPARATOR . $localeDir;
				
				// Skip symlinks and only process real directories
				if (is_dir($localePath) && !is_link($localePath)) {
					$translationFile = $localePath . DIRECTORY_SEPARATOR . $domain . '.php';
					
					if (file_exists($translationFile) && $this->isValidLocale($localeDir)) {
						$availableLocales[] = $localeDir;
					}
				}
			}
			
			self::$availableLocalesByDomain[$domain] = $availableLocales;
			return $availableLocales;
		}
		
		/**
		 * Check if a translation file exists for the given domain and locale
		 *
		 * @param string $domain Translation domain
		 * @param string $locale Locale code
		 * @return bool True if translation file exists, false otherwise
		 */
		private function hasTranslationFile(string $domain, string $locale): bool {
			$filePath = $this->getTranslationFilePath($domain, $locale);
			return file_exists($filePath);
		}
		
		/**
		 * Get preferred locale from Accept-Language header by checking filesystem
		 *
		 * Uses getAvailableLocalesForDomain() to find available locales,
		 * then uses Symfony's getPreferredLanguage() to match against Accept-Language header.
		 *
		 * @param Request $request The current HTTP request
		 * @param string $domain Translation domain to scan for available locales
		 * @return string|null Locale code or null if no valid locale found
		 */
		private function getPreferredLocaleFromFilesystem(Request $request, string $domain): ?string {
			$availableLocales = $this->getAvailableLocalesForDomain($domain);
			
			if (empty($availableLocales)) {
				return null;
			}
			
			// Use Symfony's getPreferredLanguage to match against Accept-Language header
			return $request->getPreferredLanguage($availableLocales);
		}
		
		/**
		 * Derive domain name from controller class name
		 *
		 * Transformation:
		 * - App\Controllers\AdminController -> "admin"
		 * - App\Controllers\UserProfileController -> "user_profile"
		 * - App\Controllers\APIController -> "api"
		 * - App\Controllers\Admin -> "admin" (no suffix)
		 *
		 * Strips namespace and "Controller" suffix (if present), converts to snake_case
		 *
		 * @param MethodContextInterface $context The method execution context
		 * @return string Derived domain name (snake_case)
		 */
		private function deriveFromController(MethodContextInterface $context): string {
			// Get fully qualified class name
			$className = get_class($context->getClass());
			
			// Extract class name from namespace (App\Controllers\AdminController -> AdminController)
			$parts = explode('\\', $className);
			$shortName = end($parts);
			
			// Class name cannot be just "Controller" with no prefix
			if ($shortName === 'Controller') {
				throw new \RuntimeException(
					"Cannot derive domain from controller '{$className}' - class name cannot be just 'Controller'"
				);
			}
			
			// Remove "Controller" suffix if present (AdminController -> Admin)
			if (str_ends_with($shortName, 'Controller')) {
				$shortName = substr($shortName, 0, -10); // Remove 'Controller' (10 chars)
			}
			
			// Convert to snake_case (UserProfile -> user_profile)
			return StringInflector::snakeCase($shortName);
		}
	}