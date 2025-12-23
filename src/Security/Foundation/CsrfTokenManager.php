<?php
	
	namespace Quellabs\Canvas\Security\Foundation;
	
	use Random\RandomException;
	use Symfony\Component\HttpFoundation\Session\SessionInterface;
	
	/**
	 * Manages Cross-Site Request Forgery (CSRF) tokens for protecting against
	 * malicious requests. Supports multiple token intentions and automatic
	 * token lifecycle management.
	 */
	class CsrfTokenManager {
		
		/** @var int Length of generated tokens in bytes */
		private const int TOKEN_LENGTH = 32;
		
		/** @var string Session key for storing CSRF tokens */
		private const string SESSION_KEY = '_csrf_tokens';
		
		/** @var SessionInterface The session interface for token storage */
		private SessionInterface $session;
		
		/** @var int Maximum number of tokens to store per intention (prevents session bloat) */
		private int $maxTokens;

		/**
		 * CsrfTokenManager Constructor
		 * @param SessionInterface $session
		 * @param int $maxTokens
		 */
		public function __construct(SessionInterface $session, int $maxTokens = 10) {
			$this->maxTokens = $maxTokens;
			$this->session = $session;
		}
		
		/**
		 * Creates a cryptographically secure random token and stores it in the session.
		 * Each token is associated with an intention to allow multiple forms/actions.
		 * @param string $intention The intention/purpose of the token (e.g., 'login', 'delete_user')
		 * @return string The generated token as a hex string
		 * @throws RandomException
		 */
		public function generateToken(string $intention = 'default'): string {
			// Generate cryptographically secure random token
			$token = bin2hex(random_bytes(self::TOKEN_LENGTH));
			
			// Store token in session for later validation
			$this->storeToken($intention, $token);
			
			// Return the token
			return $token;
		}
		
		/**
		 * Checks if the provided token exists in the session for the given intention.
		 * Upon successful validation, the token is removed (single-use).
		 * @param string $token The token to validate
		 * @param string $intention The intention the token was generated for
		 * @return bool True if token is valid, false otherwise
		 */
		public function validateToken(string $token, string $intention = 'default'): bool {
			// Get all stored tokens for this intention
			$tokens = $this->getStoredTokens($intention);
			
			// Check if token exists in stored tokens (strict comparison)
			if (in_array($token, $tokens, true)) {
				// Remove token after use (single-use tokens)
				$this->removeToken($intention, $token);
				return true;
			}
			
			return false;
		}
		
		/**
		 * Returns the most recently generated token for the given intention.
		 * If no tokens exist, generates a new one.
		 * @param string $intention The intention to get a token for
		 * @return string The token
		 */
		public function getToken(string $intention = 'default'): string {
			// Get existing tokens for this intention
			$tokens = $this->getStoredTokens($intention);
			
			// If no tokens exist, generate a new one
			if (empty($tokens)) {
				return $this->generateToken($intention);
			}
			
			// Return the most recent token
			return end($tokens);
		}
		
		/**
		 * Adds the token to the session storage and enforces the maximum
		 * token limit to prevent session bloat.
		 * @param string $intention The intention/purpose of the token
		 * @param string $token The token to store
		 */
		private function storeToken(string $intention, string $token): void {
			// Get all tokens from session (organized by intention)
			$allTokens = $this->session->get(self::SESSION_KEY, []);
			
			// Get tokens for this specific intention
			$tokens = $allTokens[$intention] ?? [];
			
			// Add new token to the end of the array
			$tokens[] = $token;
			
			// Limit number of tokens to prevent session bloat
			// Keep only the most recent tokens
			if (count($tokens) > $this->maxTokens) {
				$tokens = array_slice($tokens, -$this->maxTokens);
			}
			
			// Update session with new token list
			$allTokens[$intention] = $tokens;
			$this->session->set(self::SESSION_KEY, $allTokens);
		}
		
		/**
		 * Retrieve stored tokens for a given intention
		 * @param string $intention The intention to get tokens for
		 * @return array Array of tokens for the given intention
		 */
		private function getStoredTokens(string $intention): array {
			// Get all tokens from session
			$allTokens = $this->session->get(self::SESSION_KEY, []);
			
			// Return tokens for this intention, or empty array if none exist
			return $allTokens[$intention] ?? [];
		}
		
		/**
		 * Removes the token from the session after successful validation.
		 * This ensures tokens are single-use only.
		 * @param string $intention The intention the token belongs to
		 * @param string $token The token to remove
		 */
		private function removeToken(string $intention, string $token): void {
			// Get all tokens from session
			$allTokens = $this->session->get(self::SESSION_KEY, []);
			
			// Check if this intention has any tokens
			if (isset($allTokens[$intention])) {
				// Filter out the specific token
				$tokens = array_filter($allTokens[$intention], fn($t) => $t !== $token);
				
				// Re-index array to maintain clean indices
				$allTokens[$intention] = array_values($tokens);
				
				// Update session with modified token list
				$this->session->set(self::SESSION_KEY, $allTokens);
			}
		}
	}