<?php

	namespace Quellabs\Canvas\Output;

	use Quellabs\Canvas\Inspector\Helpers\HtmlAnalyzer;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Symfony\Component\HttpFoundation\StreamedResponse;
	use Symfony\Component\HttpFoundation\BinaryFileResponse;

	/**
	 * Collapses whitespace in buffered HTML while preserving embedded content.
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
			$protectedPattern = '~<!--.*?-->|<(script|style|pre|textarea|svg|math|template|code|xmp)\b(?:"[^"]*"|\'[^\']*\'|[^\'">])*?>.*?</\1\s*>~is';
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
		 * Collapses whitespace in text nodes without changing tag attributes.
		 * @param string $markup
		 * @return string
		 */
		private function minifyMarkup(string $markup): string {
			// Quoted attribute values may contain whitespace or > characters.
			$tagPattern = '~<(?:"[^"]*"|\'[^\']*\'|[^\'">])*>~s';
			$matchCount = preg_match_all($tagPattern, $markup, $matches, PREG_OFFSET_CAPTURE);
			if ($matchCount === false) {
				return $markup;
			}

			$result = '';
			$offset = 0;
			$previousTag = null;
			foreach ($matches[0] as $match) {
				$text = substr($markup, $offset, $match[1] - $offset);
				$result .= $this->minifyText($text, $previousTag, $match[0]);
				$result .= $match[0];
				$previousTag = $match[0];
				$offset = $match[1] + strlen($match[0]);
			}

			return $result . $this->minifyText(substr($markup, $offset), $previousTag, null);
		}

		/**
		 * Collapses text whitespace and removes indentation between block tags.
		 * @param string $text
		 * @param string|null $previousTag
		 * @param string|null $nextTag
		 * @return string
		 */
		private function minifyText(string $text, ?string $previousTag, ?string $nextTag): string {
			if (trim($text) === '' && $this->isBlockTag($previousTag) && $this->isBlockTag($nextTag)) {
				return '';
			}

			return preg_replace('/[ \t\r\n]+/', ' ', $text) ?? $text;
		}

		/**
		 * Checks whether a tag normally creates a block boundary.
		 * @param string|null $tag
		 * @return bool
		 */
		private function isBlockTag(?string $tag): bool {
			if ($tag === null || !preg_match('~^</?([a-z][a-z0-9]*)\b~i', $tag, $match)) {
				return false;
			}

			return in_array(strtolower($match[1]), [
				'html', 'head', 'body', 'div', 'section', 'article', 'main', 'header', 'footer',
				'nav', 'ul', 'ol', 'li', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th',
				'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
			], true);
		}
	}
