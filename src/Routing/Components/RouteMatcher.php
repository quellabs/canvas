<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\Canvas\Annotations\Route;
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	use Quellabs\Canvas\Routing\SegmentTypes;
	use Quellabs\Canvas\Routing\Strategies\SegmentMatchingStrategyInterface;
	use Quellabs\Canvas\Routing\Strategies\StaticSegmentStrategy;
	use Quellabs\Canvas\Routing\Strategies\VariableSegmentStrategy;
	use Quellabs\Canvas\Routing\Strategies\SingleWildcardStrategy;
	use Quellabs\Canvas\Routing\Strategies\MultiWildcardStrategy;
	use Quellabs\Canvas\Routing\Strategies\PartialVariableStrategy;
	
	/**
	 * RouteMatcher
	 *
	 * Handles the final matching phase of URL routing by comparing incoming requests
	 * against pre-filtered route candidates using compiled route patterns.
	 *
	 * This class takes route candidates that have already passed through pre-filtering
	 * (HTTP method, segment count, static segment filtering) and performs the detailed
	 * pattern matching to determine exact matches and extract route variables.
	 *
	 * The matcher uses a strategy pattern to handle different segment types:
	 * - Static segments: exact string matching
	 * - Variable segments: parameter extraction with optional type constraints
	 * - Wildcard segments: single (*) and multi (**) segment consumption
	 * - Partial variables: mixed static/dynamic segments (e.g., "v{path:**}")
	 *
	 * @phpstan-import-type CompiledSegment from RouteCandidateFilter
	 *
	 * @phpstan-type RouteData array{
	 *     controller: string,
	 *     method: string,
	 *     route_path: string,
	 *     http_methods: list<string>,
	 *     variables: array<string, mixed>,
	 *     compiled_pattern: list<array{
	 *         type: string,
	 *         original?: string,
	 *         is_multi_wildcard?: bool
	 *     }>,
	 *     priority: int,
	 *     route: Route
	 * }
	 *
	 * @phpstan-type MatchedRoute array{
	 *     compiled_pattern: list<CompiledSegment>,
	 *     http_methods: list<string>,
	 *     controller: string,
	 *     method: string,
	 *     route: Route,
	 *     variables: array<string, mixed>
	 * }
	 */
	class RouteMatcher {
		
		/** @var array<string, SegmentMatchingStrategyInterface> */
		private array $strategies;
		
		/** @var bool True if a trailing slash is a different route */
		private bool $matchTrailingSlashes;
		
		/**
		 * RouteMatcher constructor.
		 * Pre-initializes all strategy instances so they can be reused across matches.
		 */
		public function __construct(bool $matchTrailingSlashes = false) {
			// True if a trailing slash is a different route
			$this->matchTrailingSlashes = $matchTrailingSlashes;
			
			// Both MULTI_WILDCARD and MULTI_WILDCARD_VAR share the same strategy because the
			// difference (named vs anonymous capture) is handled inside the strategy itself,
			// not by dispatching to a different class.
			$this->strategies = [
				SegmentTypes::STATIC             => new StaticSegmentStrategy(),
				SegmentTypes::VARIABLE           => new VariableSegmentStrategy(),
				SegmentTypes::SINGLE_WILDCARD    => new SingleWildcardStrategy(),
				SegmentTypes::MULTI_WILDCARD     => new MultiWildcardStrategy(),
				SegmentTypes::MULTI_WILDCARD_VAR => new MultiWildcardStrategy(),
				SegmentTypes::PARTIAL_VARIABLE   => new PartialVariableStrategy(),
			];
		}
		
		/**
		 * Match a URL against a single route.
		 * @param RouteData $routeData Complete route configuration
		 * @param list<string> $requestSegments URL segments
		 * @param string $originalUrl Full original URL (used for trailing slash check)
		 * @param string $requestMethod HTTP method (GET, POST, etc.)
		 * @return MatchedRoute|null Matched route with extracted variables, or null on failure
		 */
		public function matchRoute(array $routeData, array $requestSegments, string $originalUrl, string $requestMethod): ?array {
			// Reject mismatched HTTP methods before doing any pattern work.
			if (!$this->httpMethodIsAllowed($requestMethod, $routeData['http_methods'])) {
				return null;
			}
			
			// Trailing-slash enforcement is opt-in; skip the check when the feature is disabled.
			if ($this->matchTrailingSlashes && !$this->trailingSlashMatches($originalUrl, $routeData['route_path'])) {
				return null;
			}
			
			// Static routes get a dedicated fast path: no variable extraction, just literal comparison.
			$compiledPattern = $routeData['compiled_pattern'];
			$segmentCount = count($requestSegments);
			$patternCount = count($compiledPattern);
			
			if ($this->isStaticRoute($compiledPattern)) {
				return $this->matchStaticRoute($compiledPattern, $requestSegments, $routeData, $segmentCount, $patternCount);
			}
			
			return $this->matchDynamicRoute($compiledPattern, $requestSegments, $routeData, $segmentCount, $patternCount);
		}
		
		// -------------------------------------------------------------------------
		// Pre-checks
		// -------------------------------------------------------------------------
		
		/**
		 * Check whether the incoming HTTP method is accepted by this route.
		 * Strict comparison prevents "get" accidentally matching "GET".
		 * @param string $requestMethod Incoming method (e.g. "GET")
		 * @param list<string> $allowedMethods Methods declared on the route
		 */
		private function httpMethodIsAllowed(string $requestMethod, array $allowedMethods): bool {
			return in_array($requestMethod, $allowedMethods, true);
		}
		
		/**
		 * Check that trailing slash presence matches between the request URL and route path.
		 * Root paths ("/" vs "/") are compared exactly. For all other paths,
		 * both must either end with a slash or neither must.
		 */
		private function trailingSlashMatches(string $originalUrl, string $routePath): bool {
			// Root is a special case: "/" ends with a slash but is not a "trailing" slash in
			// the conventional sense, so we compare the two strings directly rather than
			// applying the ends-with check that would make every root request match every root route.
			if ($originalUrl === '/' || $routePath === '/') {
				return $originalUrl === $routePath;
			}
			
			// For all other paths, require that both either carry a trailing slash or neither does.
			return str_ends_with($originalUrl, '/') === str_ends_with($routePath, '/');
		}
		
		// -------------------------------------------------------------------------
		// Static route matching
		// -------------------------------------------------------------------------
		
		/**
		 * Return true when every segment in the compiled pattern is a static (literal) segment.
		 * Empty patterns are treated as static (root path).
		 * @param list<CompiledSegment> $compiledPattern
		 * @return bool
		 */
		private function isStaticRoute(array $compiledPattern): bool {
			foreach ($compiledPattern as $segment) {
				// A single dynamic segment disqualifies the entire route from the fast path.
				if (!SegmentTypes::isStatic($segment)) {
					return false;
				}
			}
			
			// All segments passed, or the pattern is empty (root).
			return true;
		}
		
		/**
		 * Match a fully static route by comparing each segment as a literal string.
		 * Static routes must have an exact segment count and every segment must match
		 * character-for-character. No variable extraction takes place.
		 * @param list<CompiledSegment> $compiledPattern
		 * @param list<string> $requestSegments
		 * @param RouteData $routeData
		 * @param int $segmentCount
		 * @param int $patternCount
		 * @return MatchedRoute|null
		 */
		private function matchStaticRoute(array $compiledPattern, array $requestSegments, array $routeData, int $segmentCount, int $patternCount): ?array {
			// Static routes have no wildcards so a length mismatch is an immediate failure.
			if ($segmentCount !== $patternCount) {
				return null;
			}
			
			for ($i = 0; $i < $patternCount; $i++) {
				if (
					// Guard against a malformed compiled segment that is missing its literal value.
					!isset($compiledPattern[$i]['original']) ||

					// The request segment must be byte-identical to the compiled literal.
					$compiledPattern[$i]['original'] !== $requestSegments[$i]
				) {
					return null;
				}
			}
			
			// All segments matched; pass an empty variables map since static routes capture nothing.
			return $this->buildMatchResult($compiledPattern, $routeData, []);
		}
		
		// -------------------------------------------------------------------------
		// Dynamic route matching
		// -------------------------------------------------------------------------
		
		/**
		 * Validates that the request has an acceptable number of segments before running
		 * the full pattern match. For wildcard routes the minimum required count is used;
		 * for non-wildcard dynamic routes an exact count is required.
		 * @param list<CompiledSegment> $compiledPattern
		 * @param list<string> $requestSegments
		 * @param RouteData $routeData
		 * @param int $segmentCount
		 * @param int $patternCount
		 * @return MatchedRoute|null
		 */
		private function matchDynamicRoute(array $compiledPattern, array $requestSegments, array $routeData, int $segmentCount, int $patternCount): ?array {
			// Cheap structural check before spinning up the strategy machinery.
			if (!$this->segmentCountIsAcceptable($compiledPattern, $segmentCount, $patternCount)) {
				return null;
			}
			
			// $variables is populated by reference inside runStrategyMatch so that the
			// strategy loop can accumulate captures without returning them through the call stack.
			$variables = [];
			
			if (!$this->runStrategyMatch($requestSegments, $compiledPattern, $variables)) {
				return null;
			}
			
			return $this->buildMatchResult($compiledPattern, $routeData, $variables);
		}
		
		/**
		 * Determine whether the number of incoming URL segments is acceptable for this pattern.
		 *
		 * Wildcard patterns can absorb a variable number of segments, so only a
		 * minimum bound applies. Non-wildcard dynamic patterns (variables only) still
		 * require an exact count because every segment maps one-to-one.
		 *
		 * @param list<CompiledSegment> $compiledPattern
		 * @param int $segmentCount
		 * @param int $patternCount
		 * @return bool
		 */
		private function segmentCountIsAcceptable(array $compiledPattern, int $segmentCount, int $patternCount): bool {
			if ($this->patternContainsWildcard($compiledPattern)) {
				// Wildcard routes can consume more (or fewer, for **) segments than the pattern
				// has entries, so only enforce the floor, not an exact count.
				return $segmentCount >= $this->minimumSegmentsRequired($compiledPattern);
			}
			
			// Pure-variable routes map one pattern segment to one request segment with no elasticity.
			return $segmentCount === $patternCount;
		}
		
		/**
		 * Return true when the pattern contains at least one wildcard segment (single or multi).
		 * @param list<CompiledSegment> $compiledPattern
		 * @return bool
		 */
		private function patternContainsWildcard(array $compiledPattern): bool {
			foreach ($compiledPattern as $segment) {
				if (SegmentTypes::isWildcard($segment) || SegmentTypes::isMultiWildcard($segment)) {
					return true;
				}
			}
			
			return false;
		}
		
		/**
		 * Calculate the minimum number of URL segments required to satisfy this pattern.
		 *
		 * Multi-wildcards (**) can match zero segments, so they do not contribute to
		 * the minimum. Every other segment type (static, variable, single wildcard,
		 * partial variable) requires at least one segment.
		 *
		 * @param list<CompiledSegment> $compiledPattern
		 * @return int
		 */
		private function minimumSegmentsRequired(array $compiledPattern): int {
			$minimum = 0;
			
			foreach ($compiledPattern as $segment) {
				// Multi-wildcards are the only segment type that can match zero URL segments,
				// so they are intentionally excluded from the minimum count.
				if (!SegmentTypes::isMultiWildcard($segment)) {
					$minimum++;
				}
			}
			
			return $minimum;
		}
		
		// -------------------------------------------------------------------------
		// Strategy-based pattern matching
		// -------------------------------------------------------------------------
		
		/**
		 * Walk through the compiled pattern and match each segment using its strategy.
		 *
		 * Each strategy receives the current pattern segment and the shared MatchingContext
		 * (which holds both the request cursor and accumulated variables) and returns one of:
		 * - COMPLETE_MATCH: the strategy consumed all remaining segments in one go (multi-wildcard)
		 * - NO_MATCH: this route cannot match; abort immediately
		 * - CONTINUE_MATCHING: segment matched, advance both cursors and continue
		 *
		 * After the loop, the context performs a final validation to ensure no unconsumed
		 * request segments remain.
		 *
		 * @param list<string> $requestSegments
		 * @param list<CompiledSegment> $compiledPattern
		 * @param array<string, mixed> $variables Populated with extracted route variables on success
		 */
		private function runStrategyMatch(array $requestSegments, array $compiledPattern, array &$variables): bool {
			$context = new MatchingContext($requestSegments, $compiledPattern);
			
			// Iterate over pattern segments, not request segments, because wildcard strategies
			// advance the request cursor by more than one step internally.
			while ($context->hasMoreSegments()) {
				$segment = $context->getCurrentRouteSegment();
				$strategy = $this->getStrategy($segment['type']);
				$result = $strategy->match($segment, $context);
				
				if ($result === MatchResult::COMPLETE_MATCH) {
					// The strategy (typically MultiWildcard) consumed the remainder of the request
					// in one call, so there is nothing left to iterate over.
					$variables = $context->getVariables();
					return true;
				}
				
				if ($result === MatchResult::NO_MATCH) {
					// Fail fast: no backtracking is attempted, so one failed segment ends the match.
					return false;
				}
				
				// MatchResult::CONTINUE_MATCHING — advance and process next segment
				$context->advance();
			}
			
			// The pattern is exhausted; collect whatever variables the strategies captured.
			$variables = $context->getVariables();
			
			// Confirm that every request segment was consumed. If the request had more segments
			// than the pattern covered, this returns false and the route is rejected.
			return $context->validateFinalMatch();
		}
		
		/**
		 * Retrieve the pre-initialized strategy instance for a given segment type.
		 * @param string $segmentType
		 * @return SegmentMatchingStrategyInterface
		 * @throws \InvalidArgumentException When no strategy exists for the given type
		 */
		private function getStrategy(string $segmentType): SegmentMatchingStrategyInterface {
			if (!isset($this->strategies[$segmentType])) {
				throw new \InvalidArgumentException("Unknown segment type: {$segmentType}");
			}
			
			return $this->strategies[$segmentType];
		}
		
		// -------------------------------------------------------------------------
		// Result construction
		// -------------------------------------------------------------------------
		
		/**
		 * Assemble the MatchedRoute array from a successful match.
		 * @param list<CompiledSegment> $compiledPattern
		 * @param RouteData $routeData
		 * @param array<string, mixed> $variables Extracted route variables (empty for static routes)
		 * @return MatchedRoute
		 */
		private function buildMatchResult(array $compiledPattern, array $routeData, array $variables): array {
			return [
				'compiled_pattern' => $compiledPattern,
				'http_methods'     => $routeData['http_methods'],
				'controller'       => $routeData['controller'],
				'method'           => $routeData['method'],
				'route'            => $routeData['route'],
				'variables'        => $variables,
			];
		}
	}