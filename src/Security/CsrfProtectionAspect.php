<?php
	
	namespace Quellabs\Canvas\Security;
	
	use Quellabs\Canvas\Security\Foundation\CsrfTokenManager;
	use Quellabs\Contracts\AOP\BeforeAspect;
	use Quellabs\Contracts\AOP\MethodContext;
	use Symfony\Component\HttpFoundation\JsonResponse;
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
	 * - Provides appropriate error responses for both AJAX and regular requests
	 * - Automatically adds CSRF tokens to request attributes for use in controllers/templates
	 */
	class CsrfProtectionAspect implements BeforeAspect {
		
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
		
		/** @var array HTTP methods that are exempt from CSRF protection (safe methods) */
		private array $exemptMethods;
		
		/** @var int Maximum number of tokens to store per intention (prevents session bloat) **/
		private int $maxTokens;
		
		/**
		 * Constructor
		 * @param string $tokenName Name of the token field in forms
		 * @param string $headerName Name of the header for AJAX requests
		 * @param string $intention Token intention/purpose for scoping
		 * @param array $exemptMethods HTTP methods exempt from CSRF protection
		 * @param int $maxTokens Maximum number of tokens to store per intention (prevents session bloat)
		 */
		public function __construct(
			string           $tokenName = self::DEFAULT_TOKEN_NAME,
			string           $headerName = self::DEFAULT_HEADER_NAME,
			string           $intention = 'default',
			array            $exemptMethods = ['GET', 'HEAD', 'OPTIONS'],
			int              $maxTokens = 10
		) {
			$this->exemptMethods = $exemptMethods;
			$this->intention = $intention;
			$this->headerName = $headerName;
			$this->tokenName = $tokenName;
			$this->maxTokens = $maxTokens;
		}
		
		/**
		 * This method is called before the intercepted method executes.
		 * It validates CSRF tokens for state-changing requests and adds tokens
		 * to the request for use in controllers and templates.
		 * @param MethodContext $context The method execution context
		 * @return Response|null Returns error response if validation fails, null to continue execution
		 */
		public function before(MethodContext $context): ?Response {
			// Fetch the request
			$request = $context->getRequest();
			
			// Create the token manager
			$csrfManager = new CsrfTokenManager($request->getSession(), $this->maxTokens);
			
			// Skip CSRF protection for safe methods (GET, HEAD, OPTIONS)
			// These methods should not change server state, so CSRF protection is not needed
			if (in_array($request->getMethod(), $this->exemptMethods)) {
				$this->addTokenToRequest($csrfManager, $request);
				return null; // Continue with normal execution
			}
			
			// Validate CSRF token for state-changing requests (POST, PUT, DELETE, PATCH)
			if (!$this->validateCsrfToken($csrfManager, $request)) {
				return $this->createErrorResponse($request);
			}
			
			// Add fresh token to request for use in response/templates
			$this->addTokenToRequest($csrfManager, $request);
			
			// Continue with normal execution
			return null;
		}
		
		/**
		 * Creates appropriate error response for CSRF validation failure
		 *
		 * Returns different response formats based on request type:
		 * - JSON response for AJAX requests
		 * - Plain text response for regular form submissions
		 *
		 * @param Request $request The HTTP request
		 * @return Response The error response
		 */
		protected function createErrorResponse(Request $request): Response {
			// Handle AJAX requests with JSON response
			if ($request->isXmlHttpRequest()) {
				return new JsonResponse([
					'error'   => 'CSRF token validation failed',
					'message' => 'Invalid or missing CSRF token'
				], 403);
			}
			
			// Handle regular form submissions with plain text response
			return new Response('CSRF token validation failed', 403);
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
			if (!$token) {
				$token = $request->headers->get($this->headerName);
			}
			
			// No token found in either location
			if (!$token) {
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
			// Make token available to controllers and templates
			$token = $csrfManager->getToken($this->intention);
			$request->attributes->set('csrf_token', $token);
			$request->attributes->set('csrf_token_name', $this->tokenName);
		}
	}