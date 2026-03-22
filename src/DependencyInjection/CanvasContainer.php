<?php
	
	namespace Quellabs\Canvas\DependencyInjection;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\DependencyInjection\Autowiring\Autowirer;
	use Quellabs\DependencyInjection\Container;
	
	class CanvasContainer extends Container {
		
		private AnnotationReader $annotationReader;
		
		public function __construct(AnnotationReader $annotationReader, string $familyName = 'di') {
			$this->annotationReader = $annotationReader;
			parent::__construct($familyName);
		}
		
		protected function createAutowirer(): Autowirer {
			return new CanvasAutowirer($this, $this->annotationReader);
		}
	}