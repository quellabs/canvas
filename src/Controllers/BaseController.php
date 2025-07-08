<?php
	
	namespace Quellabs\Canvas\Controllers;
	
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
		 * The view renderer instance used for rendering templates.
		 * @var TemplateEngineInterface
		 */
		protected TemplateEngineInterface $view;
		
		/**
		 * The EntityManager (ObjectQuel)
		 * @var EntityManager|null
		 */
		protected ?EntityManager $em;
		
		/**
		 * BaseController constructor.
		 * @param TemplateEngineInterface $templateEngine The template engine to use for rendering
		 * @param EntityManager|null $entityManager
		 */
		public function __construct(TemplateEngineInterface $templateEngine, ?EntityManager $entityManager) {
			$this->view = $templateEngine;
			$this->em = $entityManager;
		}
		
		/**
		 * Returns true if an entity manager was installed, false if not.
		 * @return bool
		 */
		protected function hasEntityManager(): bool {
			return $this->em !== null;
		}
		
		/**
		 * Render a template using the injected view renderer
		 * @param string $template The template file path to render (relative to template directory)
		 * @param int $statusCode The http status code to return
		 * @param array $data Associative array of data to pass to the template as variables
		 * @return Response The response with the rendered template content attached
		 * @throws TemplateRenderException
		 */
		protected function render(string $template, array $data = [], int $statusCode=Response::HTTP_OK): Response {
			try {
				// Delegate the actual rendering to the injected template engine
				// The template engine handles template loading, data binding, and output generation
				$content = $this->view->render($template, $data);
				
				// Return the response
				return new Response($content, $statusCode);
			} catch (TemplateRenderException $e) {
				// Log with template context
				error_log("Template render failed [{$e->getTemplateName()}]: " . $e->getMessage());
				throw $e; // Let higher-level error handlers deal with it
			}
		}
		
		/**
		 * Returns JSON data
		 * @param array $data
		 * @param int $statusCode The http status code to return
		 * @return Response
		 */
		protected function json(array $data, int $statusCode=Response::HTTP_OK): Response {
			return new JsonResponse($data, $statusCode);
		}
		
		/**
		 * Returns literal text
		 * @param string $text
		 * @param int $statusCode The http status code to return
		 * @return Response
		 */
		protected function text(string $text, int $statusCode=Response::HTTP_OK): Response {
			return new Response($text, $statusCode);
		}
		
		/**
		 * Redirect the user to a different URL
		 * @param string $url The URL to redirect to
		 * @param int $statusCode The HTTP status code for the redirect (default: 302 for temporary redirect)
		 * @return RedirectResponse The redirect response
		 */
		protected function redirect(string $url, int $statusCode = Response::HTTP_FOUND): RedirectResponse {
			return new RedirectResponse($url, $statusCode);
		}
		
		/**
		 * Return a 404 Not Found response
		 * @param string $message The error message to display (default: 'Not Found')
		 * @param int $statusCode The HTTP status code for the 404
		 * @return Response The 404 response
		 */
		protected function notFound(string $message = 'Not Found', int $statusCode = Response::HTTP_NOT_FOUND): Response {
			return new Response($message, $statusCode);
		}
		
		/**
		 * Return a 403 Forbidden HTTP response.
		 * @param string $message The error message to display
		 * @param int $statusCode The HTTP status code for the 403
		 * @return Response HTTP 403 response
		 */
		protected function forbidden(string $message = 'Forbidden', int $statusCode = Response::HTTP_FORBIDDEN): Response {
			return new Response($message, $statusCode);
		}
	}