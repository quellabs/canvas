<?php
	
	namespace Quellabs\Canvas\Routing\Strategies;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	
	/**
	 * Interface for segment matching strategies in the Canvas routing system
	 *
	 * This interface defines the contract for different strategies that can be used
	 * to match route segments against URL parts during the routing process.
	 * Different implementations might handle static segments, dynamic parameters,
	 * wildcards, or other special routing patterns.
	 */
	interface SegmentMatchingStrategyInterface {
		
		/**
		 * Match a segment against the current URL position
		 *
		 * This method attempts to match a compiled route segment against the current
		 * position in the URL being processed. The segment contains metadata about
		 * how to perform the match (e.g., static text, parameter pattern, constraints).
		 *
		 * @param array $segment The compiled route segment containing matching rules,
		 *                      patterns, parameter names, and other metadata needed
		 *                      to perform the match operation
		 * @param MatchingContext $context The matching context containing the current
		 *                               URL being processed, current position, and
		 *                               other state information needed for matching
		 * @return MatchResult The result of the matching attempt, indicating success
		 *                     or failure, any captured parameters, and how many URL
		 *                     segments were consumed during the match
		 */
		public function match(array $segment, MatchingContext $context): MatchResult;
	}