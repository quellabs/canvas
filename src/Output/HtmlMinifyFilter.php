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

		private const string ATTRIBUTE_SKIP = '(?:"[^"]*"|\'[^\']*\'|[^\'">])*?';
		private const string PROTECTED_HTML_PATTERN = '~<!--.*?-->|<(script|style|pre|textarea|svg|math|template|code|xmp)\b' . self::ATTRIBUTE_SKIP . '>.*?</\1\s*>~is';
		private const string STYLE_ELEMENT_PATTERN = '~^(<style\b' . self::ATTRIBUTE_SKIP . '>)(.*)(</style\s*>)$~is';
		private const string TAG_ATTRIBUTE_PATTERN = '~([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~';
		private const string HTML_TAG_PATTERN = '~<(?:/?[a-zA-Z][a-zA-Z0-9]*|!)' . self::ATTRIBUTE_SKIP . '>~s';

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
			$tokens = $this->tokenizeMarkup($html);

			if ($tokens === null) {
				return $html;
			}

			// Walk the tokens in document order, deferring whitespace decisions across
			// comments (which are transparent boundaries) and resolving them against
			// the nearest real tags on either side.
			$result = '';
			$offset = 0;
			$previousRealTag = null;
			$pendingSegments = [];

			foreach ($tokens as $token) {
				// Text since the last token; stays unresolved until we know the next real tag.
				$pendingSegments[] = ['text' => substr($html, $offset, $token['offset'] - $offset)];
				$offset = $token['offset'] + $token['length'];

				if ($token['type'] === 'comment') {
					// Comments carry no whitespace meaning of their own, so keep them as an
					// opaque segment and let the next real tag resolve the pending text.
					$pendingSegments[] = ['raw' => $token['text']];
					continue;
				}

				if ($token['type'] === 'protected') {
					// script/style/pre/etc. act as a real tag boundary: resolve pending text now.
					$nextTag = '<' . $token['tagName'] . '>';
					$result .= $this->flushPendingText($pendingSegments, $previousRealTag, $nextTag);
					$pendingSegments = [];
					$result .= $this->minifyStyleElement($token['text']);
					$previousRealTag = '</' . $token['tagName'] . '>';
					continue;
				}

				// Ordinary tag token: resolve pending text against it, then emit it verbatim.
				$result .= $this->flushPendingText($pendingSegments, $previousRealTag, $token['text']);
				$pendingSegments = [];
				$result .= $token['text'];
				$previousRealTag = $token['text'];
			}

			// Trailing text after the last token has no following tag.
			$pendingSegments[] = ['text' => substr($html, $offset)];
			$result .= $this->flushPendingText($pendingSegments, $previousRealTag, null);

			return $result;
		}

		/**
		 * Finds protected regions and ordinary tags in document order. Drops a
		 * protected match that starts strictly inside an enclosing tag (a quoted
		 * attribute value, not a real element), and drops a tag match that falls
		 * inside a remaining protected region (a stray `<` in raw content).
		 * @param string $html
		 * @return list<array{offset: int, length: int, type: string, text: string, tagName: string|null}>|null
		 */
		private function tokenizeMarkup(string $html): ?array {
			$protectedCount = preg_match_all(self::PROTECTED_HTML_PATTERN, $html, $protectedMatches, PREG_OFFSET_CAPTURE);
			$tagCount = preg_match_all(self::HTML_TAG_PATTERN, $html, $tagMatches, PREG_OFFSET_CAPTURE);

			if ($protectedCount === false || $tagCount === false) {
				return null;
			}

			$tagRanges = [];

			foreach ($tagMatches[0] as $match) {
				$tagRanges[] = [$match[1], $match[1] + strlen($match[0])];
			}

			$tokens = [];
			$protectedRanges = [];

			foreach ($protectedMatches[0] as $index => $match) {
				$nestedInTag = false;

				foreach ($tagRanges as $tagRange) {
					if ($tagRange[0] < $match[1] && $match[1] < $tagRange[1]) {
						$nestedInTag = true;
						break;
					}
				}

				if ($nestedInTag) {
					continue;
				}

				$tagName = $protectedMatches[1][$index][0] !== '' ? strtolower($protectedMatches[1][$index][0]) : null;

				$tokens[] = [
					'offset' => $match[1],
					'length' => strlen($match[0]),
					'type' => $tagName === null ? 'comment' : 'protected',
					'text' => $match[0],
					'tagName' => $tagName,
				];

				$protectedRanges[] = [$match[1], $match[1] + strlen($match[0])];
			}

			foreach ($tagMatches[0] as $match) {
				$insideProtected = false;

				foreach ($protectedRanges as $range) {
					if ($match[1] >= $range[0] && $match[1] < $range[1]) {
						$insideProtected = true;
						break;
					}
				}

				if (!$insideProtected) {
					$tokens[] = [
						'offset' => $match[1],
						'length' => strlen($match[0]),
						'type' => 'tag',
						'text' => $match[0],
						'tagName' => null,
					];
				}
			}

			usort($tokens, static fn(array $a, array $b): int => $a['offset'] <=> $b['offset']);

			return $tokens;
		}

		/**
		 * Collapses the whitespace accumulated since the previous real tag, keeping
		 * any raw (comment) segments byte-for-byte and treating them as transparent
		 * when deciding whether the surrounding whitespace can be dropped entirely.
		 * @param list<array{text?: string, raw?: string}> $segments
		 * @param string|null $previousTag
		 * @param string|null $nextTag
		 * @return string
		 */
		private function flushPendingText(array $segments, ?string $previousTag, ?string $nextTag): string {
			$hasContent = false;

			foreach ($segments as $segment) {
				if (array_key_exists('text', $segment) && trim($segment['text']) !== '') {
					$hasContent = true;
					break;
				}
			}

			$collapseFully = !$hasContent && $this->isBlockTag($previousTag) && $this->isBlockTag($nextTag);
			$result = '';

			foreach ($segments as $segment) {
				if (array_key_exists('raw', $segment)) {
					$result .= $segment['raw'];
					continue;
				}

				if ($collapseFully) {
					continue;
				}

				if (array_key_exists('text', $segment)) {
					$result .= preg_replace('/[ \t\r\n]+/', ' ', $segment['text']) ?? $segment['text'];
				}
			}

			return $result;
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

			// Only CSS style blocks should be rewritten; an empty or absent type
			// attribute defaults to text/css per the HTML spec. Attributes are matched
			// sequentially so a quoted value cannot be mistaken for a later attribute.
			$mediaType = $this->findAttributeValue($parts[1], 'type');

			if ($mediaType !== null && $mediaType !== '' && strcasecmp($mediaType, 'text/css') !== 0) {
				return $element;
			}

			return $parts[1] . $this->minifyCss($parts[2]) . $parts[3];
		}

		/**
		 * Finds a named attribute's value on an opening tag by matching attributes
		 * left to right, so a name inside another attribute's quoted value is
		 * consumed as part of that value instead of being matched on its own.
		 * @param string $openingTag
		 * @param string $name
		 * @return string|null The attribute's value, or null when it is not present.
		 */
		private function findAttributeValue(string $openingTag, string $name): ?string {
			if (!preg_match_all(self::TAG_ATTRIBUTE_PATTERN, $openingTag, $attributes, PREG_SET_ORDER)) {
				return null;
			}

			foreach ($attributes as $attribute) {
				if (strcasecmp($attribute[1], $name) !== 0) {
					continue;
				}

				$value = $attribute[2] ?? '';

				if ($value === '') {
					$value = $attribute[3] ?? '';
				}

				if ($value === '') {
					$value = $attribute[4] ?? '';
				}

				return $value;
			}

			return null;
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
				'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'form', 'fieldset', 'blockquote',
				'figure', 'figcaption', 'dl', 'dt', 'dd', 'aside', 'address', 'hr', 'details', 'summary',
			], true);
		}
	}
