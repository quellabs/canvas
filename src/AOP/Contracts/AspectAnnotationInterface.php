<?php
	
	namespace Quellabs\Canvas\AOP\Contracts;
	
	/**
	 * Base marker interface for all aspect annotations in the Canvas framework.
	 *
	 * This interface serves as a common contract that all aspect types must implement,
	 * providing a unified way to identify and handle aspect annotations throughout
	 * the system. It acts as a marker interface with no methods, establishing a
	 * type hierarchy for the aspect-oriented programming system.
	 *
	 * All specific aspect interfaces (BeforeAspect, AfterAspect, AroundAspect, etc.)
	 * extend this interface, allowing the framework to:
	 * - Identify classes/annotations as aspects through type checking
	 * - Apply consistent processing logic across all aspect types
	 * - Enable polymorphic handling of different aspect varieties
	 * - Provide a foundation for future aspect functionality
	 *
	 * Implementation classes typically use PHP attributes (annotations) to define
	 * where and how the aspect should be applied to target methods or classes.
	 */
	interface AspectAnnotationInterface {
		// This interface intentionally contains no methods.
		// It serves as a marker interface for type identification
		// and polymorphic processing of aspect annotations.
	}