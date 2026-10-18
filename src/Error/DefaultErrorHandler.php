<?php
	
	namespace Quellabs\Canvas\Error;

	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Security\SecurityHeaderPolicyInterface;

	class DefaultErrorHandler {

		/** @var array<int, array{string, string}> Default error messages */
		const array ERRORS = [
			403 => ['Access Denied', 'You do not have permission to access this page.'],
			404 => ['Page Not Found', 'The page you requested could not be found.'],
			500 => ['Server Error', 'Something went wrong. Please try again later.'],
		];

		/** @var SecurityHeaderPolicyInterface|null Application-wide security header policy, null when not configured */
		private ?SecurityHeaderPolicyInterface $securityHeaderPolicy;

		/**
		 * Constructor
		 * @param SecurityHeaderPolicyInterface|null $securityHeaderPolicy Policy to apply to every error response, or null to skip
		 */
		public function __construct(?SecurityHeaderPolicyInterface $securityHeaderPolicy = null) {
			$this->securityHeaderPolicy = $securityHeaderPolicy;
		}

		/**
		 * Default error reporting
		 * @param \Throwable $e Exception that was thrown
		 * @param Request $request The request object
		 * @param $isDevelopment True if Canvas is in development mode
		 * @return Response The error response
		 */
		public function handle(\Throwable $e, Request $request, bool $isDevelopment): Response {
			$status = $this->resolveStatus($e);

			if ($isDevelopment) {
				$content = $this->renderDebugErrorPageContent($e);
			} else {
				$content = $this->renderProductionErrorPageContent($status);
			}

			$response = new Response($content, $status, ['Content-Type' => 'text/html']);

			if ($e instanceof ProvidesResponseHeaders) {
				// The exception computed these itself (e.g. RateLimitException's Retry-After,
				// MethodNotAllowedException's Allow); this handler never recalculates them.
				foreach ($e->getHeaders() as $name => $value) {
					$response->headers->set((string)$name, (string)$value);
				}
			}

			// No route/controller ran for this response, so no SecurityHeadersAspect could
			// have applied these; only ever sets a header that isn't already present above.
			$this->securityHeaderPolicy?->apply($request, $response);

			return $response;
		}
		
		/**
		 * Resolve the HTTP status code from the exception
		 * @param \Throwable $e
		 * @return int
		 */
		private function resolveStatus(\Throwable $e): int {
			if ($e instanceof RouteNotFoundException) {
				return Response::HTTP_NOT_FOUND;
			}

			// Only accept the exception code if it's a valid HTTP status; otherwise fall back to 500
			$code = $e->getCode();
			return $code >= 400 && $code <= 599 ? $code : Response::HTTP_INTERNAL_SERVER_ERROR;
		}
		
		/**
		 * Render detailed error page content for development
		 * @param \Throwable $exception
		 * @return string
		 */
		private function renderDebugErrorPageContent(\Throwable $exception): string {
			$errorCode = $exception->getCode();
			$errorMessage = $exception->getMessage();
			$errorFile = $exception->getFile();
			$errorLine = $exception->getLine();
			$trace = $exception->getTraceAsString();
			
			return "<!DOCTYPE html>
<html lang='eng'>
<head>
    <title>Canvas Framework Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .error-box { background: white; padding: 20px; border-left: 5px solid #dc3545; }
        .error-title { color: #dc3545; margin: 0 0 20px 0; }
        .error-message { font-size: 18px; margin-bottom: 20px; }
        .error-details { background: #f8f9fa; padding: 15px; border-radius: 4px; }
        .trace { background: #2d2d2d; color: #f8f8f2; padding: 15px; overflow-x: auto; font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class='error-box'>
        <h1 class='error-title'>Canvas Framework Error</h1>
        <div class='error-message'>" . htmlspecialchars($errorMessage) . "</div>
        <div class='error-details'>
            <strong>File:</strong> " . htmlspecialchars($errorFile) . "<br>
            <strong>Line:</strong> " . $errorLine . "<br>
            <strong>Code:</strong> " . $errorCode . "
        </div>
        <h3>Stack Trace:</h3>
        <pre class='trace'>" . htmlspecialchars($trace) . "</pre>
    </div>
</body>
</html>";
		}
		
		/**
		 * Render generic error page content for production
		 * @param int $status HTTP status code
		 * @return string
		 */
		private function renderProductionErrorPageContent(int $status): string {
			$error = self::ERRORS[$status] ?? self::ERRORS[500];
			
			return "<!DOCTYPE html>
<html lang='eng'>
<head>
    <title>{$error[0]}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; text-align: center; }
        .error-box { background: white; padding: 40px; border-radius: 8px; display: inline-block; }
        .error-title { color: #dc3545; margin: 0 0 20px 0; }
    </style>
</head>
<body>
    <div class='error-box'>
        <h1 class='error-title'>{$error[0]}</h1>
        <p>{$error[1]}</p>
        <p>If the problem persists, please contact support.</p>
    </div>
</body>
</html>";
		}
	}