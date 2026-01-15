<?php
	
	namespace Quellabs\Canvas\Inspector\Helpers;
	
	use Symfony\Component\HttpFoundation\Response;
	
	class HtmlAnalyzer {
		
		/**
		 * Check if the response is HTML content
		 * @param Response $response
		 * @param string $content
		 * @return bool
		 */
		public function isHtmlResponse(Response $response, string $content): bool {
			// Check Content-Type header first
			$contentType = $response->headers->get('Content-Type', '');
			
			// If explicitly set to non-HTML, don't inject
			if (preg_match('/application\/(json|xml|pdf|octet-stream)|text\/(plain|css|javascript)/', $contentType)) {
				return false;
			}
			
			// If explicitly HTML, inject
			if (str_contains($contentType, 'text/html')) {
				return true;
			}
			
			// If no Content-Type set, analyze content
			return $this->looksLikeHtml($content);
		}
		
		/**
		 * Analyze content to determine if it looks like HTML
		 * @param string $content
		 * @return bool
		 */
		public function looksLikeHtml(string $content): bool {
			// Empty content - not HTML
			if (trim($content) === '') {
				return false;
			}
			
			// Check for common non-HTML patterns first
			$trimmed = trim($content);
			
			// JSON response
			if ((str_starts_with($trimmed, '{') && str_ends_with($trimmed, '}')) ||
				(str_starts_with($trimmed, '[') && str_ends_with($trimmed, ']'))) {
				return false;
			}
			
			// XML response
			if (str_starts_with($trimmed, '<?xml')) {
				return false;
			}
			
			// Look for HTML indicators
			$htmlIndicators = [
				'<!DOCTYPE html',
				'<!doctype html',
				'<html',
				'<head>',
				'<body>',
				'<div',
				'<span',
				'<p>',
				'<h1>', '<h2>', '<h3>', '<h4>', '<h5>', '<h6>',
				'<title>',
				'<meta',
				'<link',
				'<script',
				'<style'
			];
			
			foreach ($htmlIndicators as $indicator) {
				if (stripos($content, $indicator) !== false) {
					return true;
				}
			}
			
			return false;
		}
		
		/**
		 * Returns the position of the </body> tag
		 * @param string $content
		 * @return false|int
		 */
		public function getEndOfBodyPosition(string $content): false|int {
			return strpos($content, "</body>");
		}
	}