<?php
	
	namespace Quellabs\Canvas\DependencyInjection;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Canvas\Discover\DependencyAwareDiscover;
	use Quellabs\DependencyInjection\Autowiring\Autowirer;
	use Quellabs\DependencyInjection\Container;
	use Quellabs\DependencyInjection\Provider\DefaultServiceProvider;
	use Quellabs\Discover\Scanner\ComposerScanner;
	
	class CanvasContainer extends Container {
		
		private AnnotationReader $annotationReader;
		
		/**
		 * Constructs the container using DependencyAwareDiscover in place of the
		 * base Discover, so that service providers with constructor dependencies
		 * are autowired correctly during the initial provider registration pass.
		 *
		 * parent::__construct() is intentionally skipped — it creates a bare Discover
		 * internally which cannot autowire provider constructors. We replicate its
		 * initialization here, substituting DependencyAwareDiscover so that
		 * Container::instantiate() is available to providers before registration runs.
		 */
		public function __construct(AnnotationReader $annotationReader, string $familyName = 'di') {
			$this->annotationReader = $annotationReader;
			
			// Replicate parent::__construct() with DependencyAwareDiscover instead of
			// bare Discover. Order matters: autowire must exist before registerProviders()
			// so that instantiate() works when DependencyAwareDiscover calls it.
			$this->discovery = new DependencyAwareDiscover($this);
			$this->discovery->addScanner(new ComposerScanner($familyName));
			$this->discovery->discover();
			
			$this->defaultProvider = new DefaultServiceProvider($this->discovery);
			$this->autowire = $this->createAutowirer();
			$this->registerProviders();
		}
		
		/**
		 * Creates a new autowirer class
		 * @return Autowirer
		 */
		protected function createAutowirer(): Autowirer {
			return new CanvasAutowirer($this, $this->annotationReader);
		}
	}