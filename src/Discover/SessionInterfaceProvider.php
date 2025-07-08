<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	use Symfony\Component\HttpFoundation\Session\SessionInterface;
	
	/**
	 * Service provider for Symfony session objects.
	 */
	class SessionInterfaceProvider extends ServiceProvider {
		
		/**
		 * The session instance managed by this provider.
		 * @var SessionInterface
		 */
		private SessionInterface $session;
		
		/**
		 * Creates a new session provider with the given session instance.
		 * @param SessionInterface $session The session to be provided by the container
		 */
		public function __construct(SessionInterface $session) {
			$this->session = $session;
		}
		
		/**
		 * Checks whether this provider can create instances of the requested type.
		 * @param string $className The fully qualified class or interface name being requested
		 * @param array $metadata Additional context information (unused)
		 * @return bool True if the requested type is SessionInterface, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return $className === SessionInterface::class;
		}
		
		/**
		 * Returns the session instance managed by this provider.
		 * @param string $className The requested class name (must be SessionInterface)
		 * @param array $dependencies Resolved dependencies (unused - session is pre-configured)
		 * @return SessionInterface The session instance
		 */
		public function createInstance(string $className, array $dependencies): SessionInterface {
			return $this->session;
		}
	}