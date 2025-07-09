<?php
	
	namespace Quellabs\Canvas\Routing;
	
	/**
	 * Enum for route segment matching results
	 *
	 * Defines the possible outcomes when a strategy attempts to match
	 * a route segment against a URL segment during route resolution.
	 */
	enum MatchResult {
		/**
		 * Route completely matched, stop processing
		 * Used when a multi-wildcard consumes all remaining segments
		 */
		case COMPLETE_MATCH;
		
		/**
		 * Segment didn't match, route fails
		 * Used when validation fails or patterns don't match
		 */
		case NO_MATCH;
		
		/**
		 * Segment matched, continue to next
		 * Used for successful matches that require further processing
		 */
		case CONTINUE_MATCHING;
	}