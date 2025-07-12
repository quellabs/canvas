<?php
	
	namespace Quellabs\Canvas\Routing;
	
	/**
	 * Context object that maintains state during the route matching process
	 *
	 * This class encapsulates all the state needed during route matching,
	 * providing a clean interface for strategies to interact with the
	 * matching process without exposing internal implementation details.
	 */
	class MatchingContext {
		private array $requestUrl;
		private array $compiledPattern;
		private array $variables = [];
		private int $urlIndex = 0;
		private int $routeIndex = 0;
		
		/**
		 * MatchingContext constructor
		 * @param array $requestUrl
		 * @param array $compiledPattern
		 */
		public function __construct(array $requestUrl, array $compiledPattern) {
			$this->requestUrl = $requestUrl;
			$this->compiledPattern = $compiledPattern;
		}
		
		/**
		 * Check if there are more segments to process in both URL and route
		 */
		public function hasMoreSegments(): bool {
			return $this->routeIndex < count($this->compiledPattern) && $this->urlIndex < count($this->requestUrl);
		}
		
		/**
		 * Get the current route segment being processed
		 */
		public function getCurrentRouteSegment(): array {
			return $this->compiledPattern[$this->routeIndex];
		}
		
		/**
		 * Get the current URL segment being processed
		 */
		public function getCurrentUrlSegment(): string {
			return $this->requestUrl[$this->urlIndex];
		}
		
		/**
		 * Get all remaining URL segments from current position
		 */
		public function getRemainingUrlSegments(): array {
			return array_slice($this->requestUrl, $this->urlIndex);
		}
		
		/**
		 * Get all remaining route segments after current position
		 */
		public function getRemainingRouteSegments(): array {
			return array_slice($this->compiledPattern, $this->routeIndex + 1);
		}
		
		/**
		 * Advance both URL and route indices to next segment
		 */
		public function advance(): void {
			$this->urlIndex++;
			$this->routeIndex++;
		}
		
		/**
		 * Advance URL index by specified count
		 */
		public function advanceUrl(int $count = 1): void {
			$this->urlIndex += $count;
		}
		
		/**
		 * Advance route index to next segment
		 */
		public function advanceRoute(): void {
			$this->routeIndex++;
		}
		
		/**
		 * Set a variable value
		 */
		public function setVariable(string $name, string $value): void {
			$this->variables[$name] = $value;
		}
		
		/**
		 * Add a value to a variable array (for wildcards)
		 */
		public function addToVariableArray(string $name, string $value): void {
			if (!isset($this->variables[$name])) {
				$this->variables[$name] = [];
			}
			$this->variables[$name][] = $value;
		}
		
		/**
		 * Get all collected variables
		 */
		public function getVariables(): array {
			return $this->variables;
		}
		
		/**
		 * Validate that the matching process completed successfully
		 */
		public function validateFinalMatch(): bool {
			// All route segments should be processed
			if ($this->routeIndex < count($this->compiledPattern)) {
				return false;
			}
			
			// All URL segments should be processed, unless the last route segment is a multi-wildcard
			if ($this->urlIndex < count($this->requestUrl)) {
				$lastRouteSegment = end($this->compiledPattern);
				return $this->isMultiWildcardSegment($lastRouteSegment);
			}
			
			return true;
		}
		
		/**
		 * Check if a segment is a multi-wildcard type
		 */
		private function isMultiWildcardSegment(array $segment): bool {
			return in_array($segment['type'], ['multi_wildcard', 'multi_wildcard_var']) ||
				($segment['type'] === 'variable' && $segment['is_multi_wildcard']);
		}
	}