<?php
	
	namespace Quellabs\Canvas\Routing;
	
	/**
	 * Canonical PHPStan type definitions for the routing pipeline.
	 *
	 * This class contains no logic and is never instantiated.
	 * It exists solely as a PHPStan import target so all routing
	 * components share one authoritative set of type definitions.
	 *
	 * Import pattern (use only the types your file actually references):
	 *
	 *   `@phpstan-import-type CompiledSegment from RouteTypes`
	 *   `@phpstan-import-type RouteDefinition from RouteTypes`
	 *   `@phpstan-import-type RouteIndex from RouteTypes`
	 *   `@phpstan-import-type MatchedRoute from RouteTypes`
	 *   `@phpstan-import-type IntermediateRoute from RouteTypes`
	 *
	 * Data flow through the pipeline:
	 *
	 *   RouteDiscovery        → list<IntermediateRoute>  (no compiled_pattern yet)
	 *                         → list<RouteDefinition>    (after compileRoute())
	 *   RouteCandidateFilter  → RouteIndex               (built from list<RouteDefinition>)
	 *                         → list<RouteDefinition>    (filtered candidates returned)
	 *   RouteMatcher          → MatchedRoute             (RouteDefinition + extracted variables)
	 *
	 * The `variables` key intentionally does NOT appear in RouteDefinition.
	 * It is produced by RouteMatcher during pattern matching and only exists
	 * in the MatchedRoute that is returned to the caller.
	 *
	 * @phpstan-type CompiledSegment array{
	 *     type: string,
	 *     original?: string,
	 *     is_multi_wildcard?: bool
	 * }
	 *
	 * @phpstan-type RouteDefinition array{
	 *     controller: class-string,
	 *     method: string,
	 *     route_path: string,
	 *     http_methods: list<string>,
	 *     compiled_pattern: list<CompiledSegment>,
	 *     priority: int,
	 *     route: \Quellabs\Canvas\Annotations\Route
	 * }
	 *
	 * @phpstan-type RouteIndex array{
	 *     multi_level: array<int, array<string, list<RouteDefinition>>>,
	 *     segment_count: array<int, list<RouteDefinition>>,
	 *     http_methods: array<string, list<RouteDefinition>>,
	 *     prefix_tree: array<string, mixed>
	 * }
	 *
	 * @phpstan-type MatchedRoute array{
	 *     controller: class-string,
	 *     method: string,
	 *     route_path: string,
	 *     http_methods: list<string>,
	 *     compiled_pattern: list<CompiledSegment>,
	 *     priority: int,
	 *     route: \Quellabs\Canvas\Annotations\Route,
	 *     variables: array<string, mixed>
	 * }
	 *
	 * @phpstan-type IntermediateRoute array{
	 *     http_methods: list<string>,
	 *     controller: class-string,
	 *     method: string,
	 *     route: \Quellabs\Canvas\Annotations\Route,
	 *     route_path: string,
	 *     priority: int
	 * }
	 */
	abstract class RouteTypes {}