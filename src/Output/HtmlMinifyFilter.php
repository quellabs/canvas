<?php

	namespace Quellabs\Canvas\Output;

	use Quellabs\Canvas\Inspector\Helpers\HtmlAnalyzer;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Symfony\Component\HttpFoundation\StreamedResponse;
	use Symfony\Component\HttpFoundation\BinaryFileResponse;

	/**
	 * Collapses whitespace in buffered HTML and inline CSS while preserving embedded content.
	 */
	class HtmlMinifyFilter implements OutputFilterInterface {

		private const string PROTECTED_HTML_PATTERN = '~<!--.*?-->|<(script|style|pre|textarea|svg|math|template|code|xmp)\b(?:"[^"]*"|\'[^\']*\'|[^\'">])*?>.*?</\1\s*>~is';
		private const string STYLE_ELEMENT_PATTERN = '~^(<style\b(?:"[^"]*"|\'[^\']*\'|[^\'">])*?>)(.*)(</style\s*>)$~is';
		private const string STYLE_TYPE_PATTERN = '~\btype\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~i';
		private const string HTML_TAG_PATTERN = '~<(?:"[^"]*"|\'[^\']*\'|[^\'">])*>~s';

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
		 * Minifies markup and CSS while preserving other embedded content.
		 * @param string $html
		 * @return string
		 */
		private function minify(string $html): string {
			// Keep comments and raw or whitespace-sensitive elements outside markup processing.
			$matchCount = preg_match_all(self::PROTECTED_HTML_PATTERN, $html, $matches, PREG_OFFSET_CAPTURE);

			if ($matchCount === false) {
				return $html;
			}

			// Minify only the gaps between protected regions.
			$result = '';
			$offset = 0;

			foreach ($matches[0] as $match) {
				$result .= $this->minifyMarkup(substr($html, $offset, $match[1] - $offset));
				$result .= $this->minifyStyleElement($match[0]);
				$offset = $match[1] + strlen($match[0]);
			}

			return $result . $this->minifyMarkup(substr($html, $offset));
		}

		/**
		 * Minifies CSS inside a style element and leaves other protected content intact.
		 * @param string $element
		 * @return string
		 */
		private function minifyStyleElement(string $element): string {
			if (!preg_match(self::STYLE_ELEMENT_PATTERN, $element, $parts)) {
				return $element;
			}

			// Only CSS style blocks should be rewritten.
			if (preg_match(self::STYLE_TYPE_PATTERN, $parts[1], $type)) {
				$mediaType = $type[1];
				if ($mediaType === '') {
					$mediaType = $type[2] ?? '';
				}
				if ($mediaType === '') {
					$mediaType = $type[3] ?? '';
				}
				if (strcasecmp($mediaType, 'text/css') !== 0) {
					return $element;
				}
			}

			return $parts[1] . $this->minifyCss($parts[2]) . $parts[3];
		}

		/**
		 * Collapses CSS whitespace outside strings and comments.
		 * @param string $css
		 * @return string
		 */
		private function minifyCss(string $css): string {
			$result = '';
			$length = strlen($css);
			$quote = null;
			$inComment = false;
			$pendingWhitespace = false;

			for ($index = 0; $index < $length; $index++) {
				$character = $css[$index];

				if ($inComment) {
					$result .= $character;
					if ($character === '*' && $index + 1 < $length && $css[$index + 1] === '/') {
						$result .= '/';
						$index++;
						$inComment = false;
					}
					continue;
				}

				if ($quote !== null) {
					$result .= $character;
					if ($character === '\\' && $index + 1 < $length) {
						$result .= $css[++$index];
					} elseif ($character === $quote) {
						$quote = null;
					}
					continue;
				}

				if ($character === ' ' || $character === "\t" || $character === "\r" || $character === "\n") {
					$pendingWhitespace = true;
					continue;
				}

				if ($pendingWhitespace && $result !== '') {
					$result .= ' ';
				}
				$pendingWhitespace = false;

				if ($character === '/' && $index + 1 < $length && $css[$index + 1] === '*') {
					$result .= '/*';
					$index++;
					$inComment = true;
					continue;
				}

				$result .= $character;
				if ($character === '"' || $character === "'") {
					$quote = $character;
				} elseif ($character === '\\' && $index + 1 < $length) {
					$result .= $css[++$index];
				}
			}

			return $result;
		}

		/**
		 * Collapses whitespace in text nodes without changing tag attributes.
		 * @param string $markup
		 * @return string
		 */
		private function minifyMarkup(string $markup): string {
			// Quoted attribute values may contain whitespace or > characters.
			$matchCount = preg_match_all(self::HTML_TAG_PATTERN, $markup, $matches, PREG_OFFSET_CAPTURE);
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
