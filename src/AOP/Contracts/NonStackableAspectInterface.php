<?php

	namespace Quellabs\Canvas\AOP\Contracts;

	/**
	 * Marker interface for aspects where only one declaration should take effect
	 * per method, rather than every declaration across the inheritance chain and
	 * the method running independently.
	 *
	 * AspectResolver treats a class-level @InterceptWith for a NonStackableAspectInterface
	 * aspect as a default that a more specific declaration (a subclass, or the method
	 * itself) replaces outright - the ancestor's declaration is dropped, not merely
	 * joined by the new one. Declarations at the same level are unaffected: two such
	 * annotations on the same class or method are kept as-is.
	 *
	 * Implement this for aspects that pick one configuration out of several mutually
	 * exclusive options (e.g. a security header policy, an auth mode). Do not implement
	 * it for aspects where running at multiple levels is meaningful layering rather than
	 * conflicting configuration (e.g. a cache aspect nesting a class-wide cache with a
	 * tighter method-level one) - those should keep stacking, which is the default for
	 * any aspect that does not implement this interface.
	 */
	interface NonStackableAspectInterface {
		// This interface intentionally contains no methods.
		// It is a marker consulted by AspectResolver to decide override vs. stacking.
	}
