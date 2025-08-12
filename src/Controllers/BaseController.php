<?php
	
	namespace Quellabs\Canvas\Controllers;
	
	use Quellabs\DependencyInjection\Container;
	use Quellabs\ObjectQuel\EntityManager;
	use Quellabs\Contracts\Templates\TemplateEngineInterface;
	use Quellabs\Contracts\Templates\TemplateRenderException;
	use Symfony\Component\HttpFoundation\JsonResponse;
	use Symfony\Component\HttpFoundation\RedirectResponse;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Base controller providing common functionality for all controllers.
	 */
	class BaseController {
		
		/**
		 * Dependency injection container for service resolution
		 * @var Container
		 */
		private Container $container;
		
		/**
		 * BaseController constructor.
		 * @param Container $container The DI container containing registered services
		 */
		public function __construct(Container $container) {
			$this->container = $container;
		}
		
		/**
		 * Resolve a service from the dependency injection container.
		 * @template T of object
		 * @param class-string<T> $className The fully qualified class name of the service to resolve
		 * @return T|null The resolved service instance of type T, or null if resolution fails
		 */
		protected function service(string $className): ?object {
			try {
				return $this->container->get($className);
			} catch (\Throwable) {
				// Silently handle all exceptions and return null
				// This allows graceful degradation when optional services are unavailable
				return null;
			}
		}
		
		/**
		 * Convenience method to retrieve the ObjectQuel EntityManager service.
		 * The EntityManager handles database connections, query building,
		 * and entity persistence operations.
		 * @return EntityManager|null The entity manager instance, or null if not available
		 */
		protected function em(): ?EntityManager {
			return $this->service(EntityManager::class);
		}
		
		/**
		 * Convenience method to retrieve the template engine service used for
		 * rendering views and generating HTML responses. The specific implementation
		 * depends on what template engine is registered (Twig, Smarty, etc.).
		 * @return TemplateEngineInterface|null The template engine instance, or null if not available
		 */
		protected function view(): ?TemplateEngineInterface {
			return $this->service(TemplateEngineInterface::class);
		}
		
		/**
		 * Render a template and return an HTTP response.
		 * @param string $template The template file path to render (relative to template directory)
		 * @param array $data Associative array of data to pass to the template as variables
		 * @param int $statusCode The HTTP status code to return (default: 200 OK)
		 * @return Response The HTTP response with the rendered template content
		 * @throws TemplateRenderException When template rendering fails (file not found, syntax error, etc.)
		 */
		protected function render(string $template, array $data = [], int $statusCode=Response::HTTP_OK): Response {
			try {
				// Delegate the actual rendering to the injected template engine
				// The template engine handles template loading, data binding, and output generation
				$content = $this->view()->render($template, $data);
				
				// Create and return the HTTP response with rendered content
				return new Response($content, $statusCode);
			} catch (TemplateRenderException $e) {
				// Log the error with template context for debugging
				error_log("Template render failed [{$e->getTemplateName()}]: " . $e->getMessage());
				
				// Re-throw to allow higher-level error handlers to process
				// (e.g., show user-friendly error pages, send to error tracking service)
				throw $e;
			}
		}
		
		/**
		 * Return a JSON response.
		 * @param array|\JsonSerializable $data The data to serialize as JSON
		 * @param int $statusCode The HTTP status code to return (default: 200 OK)
		 * @return JsonResponse The JSON response with appropriate headers
		 */
		protected function json(array|\JsonSerializable $data, int $statusCode = Response::HTTP_OK): JsonResponse {
			// Handle objects that implement JsonSerializable interface
			if ($data instanceof \JsonSerializable) {
				return new JsonResponse($data->jsonSerialize(), $statusCode);
			}
			
			// Handle plain arrays and other JSON-encodable data
			return new JsonResponse($data, $statusCode);
		}
		
		/**
		 * Return a plain text response.
		 * @param string $text The plain text content to return
		 * @param int $statusCode The HTTP status code to return (default: 200 OK)
		 * @return Response The plain text HTTP response
		 */
		protected function text(string $text, int $statusCode=Response::HTTP_OK): Response {
			return new Response($text, $statusCode);
		}
		
		/**
		 * Redirect the user to a different URL.
		 * @param string $url The URL to redirect to (can be relative or absolute)
		 * @param int $statusCode The HTTP status code for the redirect (default: 302 temporary redirect)
		 * @return RedirectResponse The redirect response with Location header set
		 */
		protected function redirect(string $url, int $statusCode = Response::HTTP_FOUND): RedirectResponse {
			return new RedirectResponse($url, $statusCode);
		}
		
		/**
		 * Return a 404 Not Found response.
		 * @param string $message The error message to display (default: 'Not Found')
		 * @param int $statusCode The HTTP status code (default: 404, usually shouldn't be changed)
		 * @return Response The 404 HTTP response
		 */
		protected function notFound(string $message = 'Not Found', int $statusCode = Response::HTTP_NOT_FOUND): Response {
			return new Response($message, $statusCode);
		}
		
		/**
		 * Return a 403 Forbidden response.
		 * @param string $message The error message to display (default: 'Forbidden')
		 * @param int $statusCode The HTTP status code (default: 403, usually shouldn't be changed)
		 * @return Response The 403 HTTP response
		 */
		protected function forbidden(string $message = 'Forbidden', int $statusCode = Response::HTTP_FORBIDDEN): Response {
			return new Response($message, $statusCode);
		}
	}