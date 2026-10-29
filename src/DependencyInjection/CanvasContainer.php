<?php
	
	namespace Quellabs\Canvas\DependencyInjection;

	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Canvas\Discover\DependencyAwareDiscover;
	use Quellabs\DependencyInjection\Autowiring\Autowirer;
	use Quellabs\DependencyInjection\Container;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Scanner\ComposerScanner;

	class CanvasContainer extends Container {

		private AnnotationReader $annotationReader;

		/**
		 * @param AnnotationReader $annotationReader
		 * @param string $familyName The key to look for in composer.json (default: 'di')
		 */
		public function __construct(AnnotationReader $annotationReader, string $familyName = 'di') {
			$this->annotationReader = $annotationReader;
			parent::__construct($familyName);
		}

		/**
		 * Substitutes DependencyAwareDiscover so providers can be autowired.
		 * @param string $familyName The key to look for in composer.json
		 * @return Discover
		 */
		protected function createDiscovery(string $familyName): Discover {
			$discovery = new DependencyAwareDiscover($this);
			$discovery->addScanner(new ComposerScanner($familyName));
			return $discovery;
		}

		/**
		 * Creates a new autowirer class
		 * @return Autowirer
		 */
		protected function createAutowirer(): Autowirer {
			return new CanvasAutowirer($this, $this->annotationReader);
		}
	}