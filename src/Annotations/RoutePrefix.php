<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	use Quellabs\AnnotationReader\Annotation\ReflectsAnnotationParameters;
	
	/**
	 * @Annotation
	 *
	 * RoutePrefix Annotation Class
	 *
	 * This class implements an annotation interface for defining route prefixes
	 * in a routing system. It stores and provides access to route configuration
	 * parameters such as the route path and allowed HTTP methods.
	 *
	 * Used as an annotation to define route prefixes for controllers or methods
	 * in a web application routing system.
	 */
	#[\Attribute(\Attribute::TARGET_CLASS)]
	class RoutePrefix implements AnnotationInterface {
		use ReflectsAnnotationParameters;
		
		/** @var string The route prefix */
		private string $value;
		
		/**
		 * Constructs the RoutePrefix annotation.
		 * @param string $value
		 * @return void
		 */
		public function __construct(string $value) {
			$this->value = $value;
		}
		
		/**
		 * Fetches the route prefix
		 * @return string The route prefix
		 */
		public function getRoutePrefix(): string {
			return trim($this->value, '/ ');
		}
	}
