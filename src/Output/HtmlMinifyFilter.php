<?php

	namespace Quellabs\Canvas\Output;

	use Quellabs\Canvas\Inspector\Helpers\HtmlAnalyzer;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Symfony\Component\HttpFoundation\StreamedResponse;
	use Symfony\Component\HttpFoundation\BinaryFileResponse;

	/**
	 * Removes indentation between common block elements in buffered HTML responses.
	 */
	class HtmlMinifyFilter implements OutputFilterInterface {

		/**
		 * Filters eligible HTML responses and updates headers tied to the body bytes.
		 * @param Request $request
		 * @param Response $response
		 * @return void
		 */
		public function filter(Request $request, Response $response): void {
			// These responses do not expose a complete body that can be rewritten here.
			if ($response instanceof StreamedResponse || $response instanceof BinaryFileResponse) {
				return;
			}

			// Exclude status code
			if (in_array($response->getStatusCode(), [204, 205, 206, 304], true)) {
				return;
			}

			// Compressed bodies and explicit no-transform responses must keep their original bytes.
			if ($response->headers->has('Content-Encoding') || stripos((string)$response->headers->get('Cache-Control', ''), 'no-transform') !== false) {
				return;
			}

			// Ignore if no content
			$content = $response->getContent();

			if (!is_string($content) || $content === '') {
				return;
			}

			// Rendered templates can be HTML even when no Content-Type has been set yet.
			$contentType = (string)$response->headers->get('Content-Type', '');

			if ($contentType !== '') {
				if (!preg_match('~^text/html(?:\s*;|\s*$)~i', $contentType)) {
					return;
				}
			} elseif (!(new HtmlAnalyzer())->looksLikeHtml($content)) {
				return;
			}

			// Perform minification and validate that output changed
			$minified = $this->minify($content);
			
			if ($minified === $content) {
				return;
			}

			// Update the content with the minified content
			$response->setContent($minified);

			if ($response->headers->has('Content-Length')) {
				$response->headers->set('Content-Length', (string)strlen($minified));
			}

			// Validators and digests for the original bytes are invalid after filtering.
			foreach (['ETag', 'Content-MD5', 'Digest', 'Content-Digest', 'Repr-Digest'] as $header) {
				$response->headers->remove($header);
			}
		}

		/**
		 * Minifies markup outside comments and whitespace-sensitive elements.
		 * @param string $html
		 * @return string
		 */
		private function minify(string $html): string {
			// Keep comments and raw or whitespace-sensitive elements verbatim.
			$protectedPattern = '~<!--.*?-->|<(script|style|pre|textarea)\b(?:"[^"]*"|\'[^\']*\'|[^\'">])*?>.*?</\1\s*>~is';
			$matchCount = preg_match_all($protectedPattern, $html, $matches, PREG_OFFSET_CAPTURE);
			if ($matchCount === false) {
				return $html;
			}

			// Minify only the gaps between protected regions.
			$result = '';
			$offset = 0;
			foreach ($matches[0] as $match) {
				$result .= $this->minifyMarkup(substr($html, $offset, $match[1] - $offset));
				$result .= $match[0];
				$offset = $match[1] + strlen($match[0]);
			}

			return $result . $this->minifyMarkup(substr($html, $offset));
		}

		/**
		 * Removes inter-tag indentation where both tags are common block elements.
		 * @param string $markup
		 * @return string
		 */
		private function minifyMarkup(string $markup): string {
			// Leave spaces around inline elements intact because they can separate visible text.
			$block = '(?:html|head|body|div|section|article|main|header|footer|nav|ul|ol|li|table|thead|tbody|tfoot|tr|td|th|p|h[1-6])';
			$pattern = '~(</?' . $block . '\b[^>]*>)[ \t\r\n]+(?=</?' . $block . '\b)~i';
			return preg_replace($pattern, '$1', $markup) ?? $markup;
		}
	}
