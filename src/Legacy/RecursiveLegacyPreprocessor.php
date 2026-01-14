<?php
	
	namespace Quellabs\Canvas\Legacy;
	
	/**
	 * This class processes legacy PHP files by recursively discovering and processing
	 * all their include/require dependencies. It maintains a cache of processed files
	 * and rewrites include paths to point to the processed versions.
	 */
	class RecursiveLegacyPreprocessor extends LegacyPreprocessor {
		
		/**
		 * Array to track already processed files to avoid infinite recursion
		 * Format: [absolute_original_path => processed_file_path]
		 */
		private array $processedFiles = [];
		
		/**
		 * Maps original file paths to their processed counterparts
		 * Format: [original_file => processed_file]
		 */
		private array $fileMapping = [];
		
		/**
		 * Directory where processed files are cached
		 */
		private string $cacheDir;
		
		/**
		 * Base path for legacy files (used for resolving relative includes)
		 */
		private string $legacyBasePath;
		
		/**
		 * Array of path patterns to exclude from preprocessing
		 */
		private array $excludedPaths;
		
		
		/**
		 * Constructor that takes the cache directory and legacy base path
		 * @param string $cacheDir Directory where processed files will be stored
		 * @param string $legacyBasePath Base path for legacy files (default: 'legacy/')
		 */
		public function __construct(string $cacheDir, string $legacyBasePath = 'legacy/') {
			$this->cacheDir = $cacheDir;
			$this->legacyBasePath = rtrim($legacyBasePath, '/') . '/';
			$this->excludedPaths = [];
		}
		
		/**
		 * Set paths to exclude from preprocessing
		 * @param array $paths Array of path patterns to exclude (e.g., ['/vendor/', '/lib/'])
		 * @return void
		 */
		public function setExcludedPaths(array $paths): void {
			$this->excludedPaths = $paths;
		}
		
		/**
		 * Check if a file should be preprocessed or used as-is
		 * @param string $filePath Path to check
		 * @return bool True if file should be preprocessed, false to use original
		 */
		private function shouldPreprocess(string $filePath): bool {
			$normalizedPath = str_replace('\\', '/', $filePath);
			
			foreach ($this->excludedPaths as $excluded) {
				if (str_contains($normalizedPath, $excluded)) {
					return false;
				}
			}
			
			return true;
		}
		
		/**
		 * Process a legacy file and all its dependencies recursively
		 * @param string $mainFilePath Path to the main legacy file
		 * @return string Path to the processed main file
		 * @throws \Exception
		 */
		public function processFileRecursively(string $mainFilePath): string {
			// Check if file should be preprocessed at all
			if (!$this->shouldPreprocess($mainFilePath)) {
				return $mainFilePath; // Return original file path
			}
			
			// Reset state for new processing run to avoid cross-contamination
			$this->processedFiles = [];
			$this->fileMapping = [];
			
			// Process the main file and all its dependencies
			return $this->processFileWithIncludes($mainFilePath);
		}
		
		/**
		 * Process a single file and recursively process its includes
		 *
		 * This method implements a depth-first processing approach:
		 * 1. Check if file is already processed (to avoid cycles)
		 * 2. Discover all includes in the current file
		 * 3. Recursively process all includes first
		 * 4. Process the current file using parent's preprocessing
		 * 5. Rewrite include paths to point to processed files
		 * 6. Cache the result
		 *
		 * @param string $filePath Path to the file to process
		 * @return string Path to the processed file
		 * @throws \Exception If file is not found
		 */
		private function processFileWithIncludes(string $filePath): string {
			// Check if this specific file should be preprocessed
			if (!$this->shouldPreprocess($filePath)) {
				// Return original path and mark as "processed" to avoid reprocessing
				$realPath = realpath($filePath);
				
				if ($realPath) {
					$this->processedFiles[$realPath] = $realPath;
					$this->fileMapping[$realPath] = $realPath;
				}
				
				return $filePath;
			}
			
			// Normalize path to prevent issues with relative paths and symlinks
			$realPath = realpath($filePath);
			
			if (!$realPath) {
				throw new \Exception("File not found: {$filePath}");
			}
			
			// Skip if already processed (prevents infinite recursion and duplicate work)
			if (isset($this->processedFiles[$realPath])) {
				return $this->processedFiles[$realPath];
			}
			
			// Read original file content
			$content = file_get_contents($realPath);
			
			// Find all include/require statements in this file
			$includes = $this->discoverIncludes($content, dirname($realPath));
			
			// Process all discovered includes first (depth-first approach)
			// This ensures dependencies are processed before the files that depend on them
			foreach ($includes as $includeInfo) {
				$originalIncludePath = $includeInfo['resolved_path'];
				$processedIncludePath = $this->processFileWithIncludes($originalIncludePath);
				
				// Store the mapping for later path rewriting
				$this->fileMapping[$originalIncludePath] = $processedIncludePath;
			}
			
			// Now process this file's content using parent's preprocessing logic
			$processedContent = parent::preprocess($realPath);
			
			// Rewrite include paths to point to processed files instead of originals
			$processedContent = $this->rewriteIncludePaths($processedContent, dirname($realPath));
			
			// Generate a unique path for the processed file
			$processedFilePath = $this->generateProcessedFilePath($realPath);
			
			// Write the processed content to the cache directory
			file_put_contents($processedFilePath, $processedContent);
			
			// Cache the result to avoid reprocessing
			$this->processedFiles[$realPath] = $processedFilePath;
			
			// Return the path
			return $processedFilePath;
		}
		
		/**
		 * Discover all include/require statements in content
		 *
		 * This method uses regex patterns to find various forms of include statements:
		 * - include('file.php') / require('file.php')
		 * - include_once('file.php') / require_once('file.php')
		 * - include 'file.php' / require 'file.php' (without parentheses)
		 *
		 * @param string $content File content to analyze
		 * @param string $currentDir Directory of the current file (for resolving relative paths)
		 * @return array Array of include information with keys:
		 *               - original_statement: The full matched include statement
		 *               - statement_type: Type of statement (include, require, etc.)
		 *               - quote_char: Quote character used (' or ")
		 *               - include_path: The path from the include statement
		 *               - resolved_path: Absolute path to the included file
		 */
		private function discoverIncludes(string $content, string $currentDir): array {
			$includes = [];
			
			// Regex patterns to match different include statement formats
			$patterns = [
				// Matches: include('file.php') or include_once('file.php')
				'/\b(include|require|include_once|require_once)\s*\(\s*([\'"])([^\2]*?)\2\s*\)\s*;/i',
				// Matches: include 'file.php' or include_once 'file.php' (without parentheses)
				'/\b(include|require|include_once|require_once)\s+([\'"])([^\2]*?)\2\s*;/i'
			];
			
			// Process each pattern
			foreach ($patterns as $pattern) {
				if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER)) {
					foreach ($matches as $match) {
						$includePath = $match[3]; // The path from the include statement
						$resolvedPath = $this->resolveIncludePath($includePath, $currentDir);
						
						// Only process PHP files that actually exist
						if ($resolvedPath && file_exists($resolvedPath) && str_ends_with($resolvedPath, '.php')) {
							$includes[] = [
								'original_statement' => $match[0],     // Full matched statement
								'statement_type'     => $match[1],     // include, require, etc.
								'quote_char'         => $match[2],     // ' or "
								'include_path'       => $includePath,  // Original path from statement
								'resolved_path'      => $resolvedPath  // Absolute path to file
							];
						}
					}
				}
			}
			
			return $includes;
		}
		
		/**
		 * Resolve include path to absolute path
		 *
		 * This method tries multiple strategies to resolve include paths:
		 * 1. If already absolute, use as-is
		 * 2. Try relative to current file's directory
		 * 3. Try relative to legacy base path
		 * 4. Try PHP's include path using stream_resolve_include_path()
		 *
		 * @param string $includePath Path from include statement
		 * @param string $currentDir Directory of file containing the include
		 * @return string|null Resolved absolute path or null if not found
		 */
		private function resolveIncludePath(string $includePath, string $currentDir): ?string {
			// If already absolute (starts with / or Windows drive letter), return as-is
			if (str_starts_with($includePath, '/') || preg_match('/^[A-Za-z]:/', $includePath)) {
				return file_exists($includePath) ? realpath($includePath) : null;
			}
			
			// Try relative to current directory (most common case)
			$relativePath = $currentDir . '/' . $includePath;
			
			if (file_exists($relativePath)) {
				return realpath($relativePath);
			}
			
			// Try relative to legacy base path (for legacy file structure)
			$legacyPath = $this->legacyBasePath . $includePath;
			
			if (file_exists($legacyPath)) {
				return realpath($legacyPath);
			}
			
			// Try PHP's include path (searches directories in include_path ini setting)
			$foundPath = stream_resolve_include_path($includePath);
			
			if ($foundPath !== false) {
				return $foundPath;
			}
			
			// Could not resolve the path
			return null;
		}
		
		/**
		 * This method finds all include statements in the processed content and
		 * rewrites their paths to point to the processed versions of the files
		 * instead of the original files.
		 * @param string $content Content to rewrite
		 * @param string $currentDir Directory of current file (for path resolution)
		 * @return string Content with rewritten paths
		 */
		private function rewriteIncludePaths(string $content, string $currentDir): string {
			// Pattern matches include statements with or without parentheses
			$pattern = '/\b((?:include|require)(?:_once)?)\s*[\(\s]\s*([\'"])([^\2]*?)\2\s*[\)\s]*;/i';
			
			return preg_replace_callback($pattern, function ($matches) use ($currentDir) {
				$statement = $matches[1];    // include, require, etc.
				$quoteChar = $matches[2];    // ' or "
				$includePath = $matches[3];  // Original path
				
				// Resolve the original path to absolute path
				$resolvedOriginalPath = $this->resolveIncludePath($includePath, $currentDir);
				
				// Check if we have a processed version of this file
				if ($resolvedOriginalPath && isset($this->fileMapping[$resolvedOriginalPath])) {
					$processedPath = $this->fileMapping[$resolvedOriginalPath];
					
					// Try to convert back to a relative path for cleaner includes
					$newPath = $this->makeRelativePath($processedPath, $currentDir) ?: $processedPath;
					
					// Return the rewritten include statement
					return "{$statement} {$quoteChar}{$newPath}{$quoteChar};";
				}
				
				// Return original statement if no processed version found
				return $matches[0];
			}, $content);
		}
		
		/**
		 * Generate path for processed file
		 *
		 * Creates a unique filename for the processed file based on:
		 * - MD5 hash of the original path (for uniqueness)
		 * - File modification time (for cache invalidation)
		 * - Original basename (for readability)
		 *
		 * @param string $originalPath Original file path
		 * @return string Path where processed file should be stored
		 */
		private function generateProcessedFilePath(string $originalPath): string {
			// Create a unique filename based on original path and modification time
			$pathHash = md5($originalPath);           // Unique identifier for the path
			$mtime = filemtime($originalPath);        // Modification time for cache invalidation
			$basename = pathinfo($originalPath, PATHINFO_FILENAME); // Original filename (without extension)
			
			// Format: {hash}_{mtime}_{basename}.php
			return $this->cacheDir . "/{$pathHash}_{$mtime}_{$basename}.php";
		}
		
		/**
		 * This helper method attempts to create a relative path from an absolute path
		 * relative to a base directory. This makes the generated include statements
		 * cleaner and more portable.
		 * @param string $path Absolute path to make relative
		 * @param string $baseDir Base directory
		 * @return string|null Relative path or null if not possible
		 */
		private function makeRelativePath(string $path, string $baseDir): ?string {
			// Normalize both paths to absolute
			$path = realpath($path);
			$baseDir = realpath($baseDir);
			
			// Return null if either path is invalid
			if (!$path || !$baseDir) {
				return null;
			}
			
			// Simple relative path calculation - only works if path is within baseDir
			if (str_starts_with($path, $baseDir)) {
				return substr($path, strlen($baseDir) + 1);
			}
			
			// Could not create a relative path (file is outside base directory)
			return null;
		}
		
		/**
		 * Clear all processed files from cache
		 * @return int Number of files removed
		 */
		public function clearCache(): int {
			// Check if cache directory exists
			if (!is_dir($this->cacheDir)) {
				return 0;
			}
			
			// Find all PHP files in cache directory
			$files = glob($this->cacheDir . '/*.php');
			$removed = 0;
			
			// Remove each file and count successful removals
			foreach ($files as $file) {
				if (unlink($file)) {
					++$removed;
				}
			}
			
			return $removed;
		}
	}