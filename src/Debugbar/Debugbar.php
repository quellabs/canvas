<?php
	
	namespace Quellabs\Canvas\Debugbar;
	
	use Quellabs\Canvas\Configuration\Configuration;
	use Quellabs\Canvas\Debugbar\Helpers\DebugRegistry;
	use Quellabs\Canvas\Debugbar\Helpers\HtmlAnalyzer;
	use Quellabs\Contracts\Configuration\ConfigurationInterface;
	use Quellabs\Contracts\Debugbar\DebugEventCollectorInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Main debugbar class responsible for injecting debug information into HTTP responses.
	 * Provides debugging panels and analytics for web applications by modifying HTML responses.
	 */
	class Debugbar {
		
		/** @var DebugRegistry Registry that manages all debug panels */
		private DebugRegistry $registry;
		
		/** @var HtmlAnalyzer Helper for analyzing and manipulating HTML content */
		private HtmlAnalyzer $htmlAnalyzer;
		
		/**
		 * Initialize the debugbar with required dependencies.
		 * @param DebugEventCollectorInterface $eventCollector The event collector for gathering debug data
		 * @param ConfigurationInterface $config
		 */
		public function __construct(DebugEventCollectorInterface $eventCollector, ConfigurationInterface $config) {
			$this->htmlAnalyzer = new HtmlAnalyzer();
			$this->registry = new DebugRegistry($eventCollector, $config);
		}
		
		/**
		 * Inject debug information into the HTTP response if it's an HTML response.
		 * This is the main entry point for adding the debugbar to responses.
		 * @param Request $request The HTTP request object
		 * @param Response $response The HTTP response object to modify
		 */
		public function inject(Request $request, Response $response): void {
			$content = $response->getContent();
			
			// Only inject debug info into HTML responses
			if (!$this->htmlAnalyzer->isHtmlResponse($response, $content)) {
				return;
			}
			
			// Generate the debug HTML from all registered panels
			$debugHtml = $this->registry->render($request);
			
			// Inject the debug HTML into the response content
			$this->injectHtml($response, $content, $debugHtml);
		}
		
		/**
		 * Inject debug HTML into the response content at the optimal location.
		 * Attempts to insert before closing </body> tag for best compatibility.
		 * @param Response $response The response object to modify
		 * @param string $content The original response content
		 * @param string $debugHtml The debug HTML to inject
		 */
		private function injectHtml(Response $response, string $content, string $debugHtml): void {
			// Try to find the end of the body tag for optimal placement
			$bodyPos = $this->htmlAnalyzer->getEndOfBodyPosition($content);
			
			if ($bodyPos !== false) {
				// Insert debug HTML just before the closing </body> tag
				$newContent = substr($content, 0, $bodyPos) . $debugHtml . substr($content, $bodyPos);
				$response->setContent($newContent);
			} else {
				// Fall back to alternative injection methods if no body tag found
				$this->injectWithoutBodyTag($response, $content, $debugHtml);
			}
		}
		
		/**
		 * Handle debug HTML injection for responses without a proper </body> tag.
		 * Uses fallback strategies to ensure debug info is still displayed.
		 * @param Response $response The response object to modify
		 * @param string $content The original response content
		 * @param string $debugHtml The debug HTML to inject
		 */
		private function injectWithoutBodyTag(Response $response, string $content, string $debugHtml): void {
			// Strategy 1: Try to find </html> tag and insert before it
			$htmlEndPos = strripos($content, '</html>');

			if ($htmlEndPos !== false) {
				$newContent = substr($content, 0, $htmlEndPos) . $debugHtml . substr($content, $htmlEndPos);
				$response->setContent($newContent);
				return;
			}
			
			// Strategy 2: Try to find </head> tag and add a body section
			$headEndPos = strripos($content, '</head>');

			if ($headEndPos !== false) {
				// Create a body section with the debug content
				$bodyContent = "\n<body>" . $debugHtml . "</body>\n</html>";
				$newContent = substr($content, 0, $headEndPos + 7) . $bodyContent . substr($content, $headEndPos + 7);
				$response->setContent($newContent);
				return;
			}
			
			// Strategy 3: If content appears to be HTML but lacks structure, wrap it completely
			if ($this->htmlAnalyzer->looksLikeHtml($content)) {
				// Create a complete HTML document structure
				$newContent = sprintf("
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                    <title>Debug</title>
                </head>
                <body>
                    %s
                    %s
                </body>
                </html>
            ",
					$content,  // Original content
					$debugHtml // Debug information
				);
				
				$response->setContent(trim($newContent));
				
				// Set proper content type if not already set
				if (!$response->headers->has('Content-Type')) {
					$response->headers->set('Content-Type', 'text/html; charset=UTF-8');
				}
			}
		}
	}