<?php
	
	namespace Quellabs\Canvas\Security;
	
	use Quellabs\Canvas\Exceptions\CsrfTokenException;
	use Quellabs\Canvas\Security\Foundation\CsrfTokenManager;
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Random\RandomException;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * CSRF Protection Aspect
	 *
	 * Implements Cross-Site Request Forgery (CSRF) protection using AOP (Aspect-Oriented Programming).
	 * This aspect intercepts method calls to validate CSRF tokens for state-changing HTTP requests.
	 *
	 * Features:
	 * - Validates CSRF tokens for POST, PUT, DELETE, PATCH requests
	 * - Skips validation for safe methods (GET, HEAD, OPTIONS)
	 * - Supports token validation from both form data and headers
	 * - Automatically adds CSRF tokens to request attributes for use in controllers/templates
	 * - Configurable failure handling: attribute-based (default) or exception
	 *
	 * Failure modes:
	 * - Default (throwOnFailure = false): writes csrf_validation_succeeded = false and a csrf_error
	 *   array to the request attributes, then continues. The controller is responsible for checking
	 *   these attributes and deciding how to respond (e.g. re-rendering the form with an error).
	 * - throwOnFailure = true: throws CsrfTokenException, which the framework's exception handler
	 *   converts into an HTTP response. Use this when you want centralized, uniform error handling
	 *   and do not need per-controller CSRF failure logic.
	 */
	class CsrfProtectionAspect implements BeforeAspectInterface {
		
		/** @var string Default name for CSRF token in forms */
		private const string DEFAULT_TOKEN_NAME = '_csrf_token';
		
		/** @var string Default header name for CSRF token in AJAX requests */
		private const string DEFAULT_HEADER_NAME = 'X-CSRF-Token';
		
		/** @var string Name of the token field in forms */
		private string $tokenName;
		
		/** @var string Name of the header for AJAX requests */
		private string $headerName;
		
		/** @var string Intention/purpose for token generation (allows different tokens for different contexts) */
		private string $intention;
		
		/** @var array<string> HTTP methods that are exempt from CSRF protection (safe methods) */
		private array $exemptMethods;
		
		/** @var int Maximum number of tokens to store per intention (prevents session bloat) */
		private int $maxTokens;
		
		/** @var bool If true, throws CsrfTokenException on failure instead of writing to request attributes */
		private bool $throwOnFailure;
		
		/**
		 * Constructor
		 * @param string $tokenName Name of the token field in forms
		 * @param string $headerName Name of the header for AJAX requests
		 * @param string $intention Token intention/purpose for scoping
		 * @param array<string> $exemptMethods HTTP methods exempt from CSRF protection
		 * @param int $maxTokens Maximum number of tokens to store per intention (prevents session bloat)
		 * @param bool $throwOnFailure If true, throws CsrfTokenException on failure instead of writing
		 *                             failure info to request attributes. Use when you want the framework's
		 *                             central exception handler to deal with CSRF errors uniformly.
		 */
		public function __construct(
			string $tokenName = self::DEFAULT_TOKEN_NAME,
			string $headerName = self::DEFAULT_HEADER_NAME,
			string $intention = 'default',
			array  $exemptMethods = ['GET', 'HEAD', 'OPTIONS'],
			int    $maxTokens = 10,
			bool   $throwOnFailure = false
		) {
			$this->exemptMethods = $exemptMethods;
			$this->intention = $intention;
			$this->headerName = $headerName;
			$this->tokenName = $tokenName;
			$this->maxTokens = $maxTokens;
			$this->throwOnFailure = $throwOnFailure;
		}
		
		/**
		 * This method is called before the intercepted method executes.
		 * It validates CSRF tokens for state-changing requests and adds tokens
		 * to the request for use in controllers and templates.
		 * @param MethodContextInterface $context The method execution context
		 * @return Response|null Always returns null; throws CsrfTokenException if throwOnFailure is
		 *                       enabled and validation fails, otherwise writes failure info to attributes
		 * @throws RandomException
		 * @throws CsrfTokenException If throwOnFailure is true and the CSRF token is missing or invalid
		 */
		public function before(MethodContextInterface $context): ?Response {
			// Fetch the request
			$request = $context->getRequest();
			
			// Create the token manager
			$csrfManager = new CsrfTokenManager($request->getSession(), $this->maxTokens);
			
			// Skip CSRF protection for safe methods (GET, HEAD, OPTIONS).
			// These methods should not change server state, so CSRF protection is not needed.
			if (in_array($request->getMethod(), $this->exemptMethods)) {
				$request->attributes->set('csrf_validation_succeeded', true);
				$this->addTokenToRequest($csrfManager, $request);
				return null;
			}
			
			// Validate CSRF token for state-changing requests (POST, PUT, DELETE, PATCH)
			$isValid = $this->validateCsrfToken($csrfManager, $request);
			
			if ($isValid) {
				$request->attributes->set('csrf_validation_succeeded', true);
				$this->addTokenToRequest($csrfManager, $request);
				return null;
			}
			
			// Default: write failure info to request attributes and let the controller handle it.
			// A fresh token is generated here so the controller can re-render the form immediately
			// without a separate round-trip to fetch a new token.
			$request->attributes->set('csrf_validation_succeeded', false);
			$request->attributes->set('csrf_error', [
				'type'    => 'csrf_token_invalid',
				'message' => 'Invalid or missing CSRF token'
			]);
			
			// Generate fresh token for re-rendered form
			$token = $csrfManager->generateToken($this->intention);
			$request->attributes->set('csrf_token', $token);
			$request->attributes->set('csrf_token_name', $this->tokenName);
			
			// Validation failed — throw if opted in, otherwise write to attributes and continue
			if ($this->throwOnFailure) {
				throw new CsrfTokenException('Invalid or missing CSRF token');
			}
			
			// Continue to controller
			return null;
		}
		
		/**
		 * Attempts to retrieve the token from POST data first, then falls back
		 * to checking the request headers (useful for AJAX requests).
		 * @param CsrfTokenManager $csrfManager Service for generating and validating CSRF tokens
		 * @param Request $request The HTTP request
		 * @return bool True if token is valid, false otherwise
		 */
		private function validateCsrfToken(CsrfTokenManager $csrfManager, Request $request): bool {
			// Try to get token from POST data first (form submissions)
			$token = $request->request->get($this->tokenName);
			
			// Fall back to header (for AJAX requests)
			if (!is_string($token) || $token === '') {
				$headerToken = $request->headers->get($this->headerName);
				$token = is_string($headerToken) ? $headerToken : null;
			}
			
			// No token found in either location
			if (!is_string($token) || $token === '') {
				return false;
			}
			
			// Validate the token using the CSRF manager
			return $csrfManager->validateToken($token, $this->intention);
		}
		
		/**
		 * Makes the current CSRF token available to controllers and templates
		 * by adding it to the request attributes. This allows forms to include
		 * the token and templates to access it.
		 * @param CsrfTokenManager $csrfManager Service for generating and validating CSRF tokens
		 * @param Request $request The HTTP request
		 */
		private function addTokenToRequest(CsrfTokenManager $csrfManager, Request $request): void {
			$token = $csrfManager->getToken($this->intention);
			$request->attributes->set('csrf_token', $token);
			$request->attributes->set('csrf_token_name', $this->tokenName);
		}
	}