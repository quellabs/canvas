<?php
	
	namespace Quellabs\Canvas\Security;
	
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\File\UploadedFile;
	use Symfony\Component\HttpFoundation\JsonResponse;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Quellabs\Support\ComposerUtils;
	use RuntimeException;
	
	/**
	 * Secure Upload Aspect
	 *
	 * Automatically handles file upload security, validation, and storage.
	 * Implements security best practices for file uploads to prevent common attacks.
	 *
	 * Security measures:
	 * - File type validation using MIME type and extension checking
	 * - File size limits with configurable maximums
	 * - Filename sanitization to prevent directory traversal
	 * - Virus scanning integration (if available)
	 * - Content validation for image files
	 * - Execution prevention via .htaccess (Apache only — see note below)
	 *
	 * Deployment requirements:
	 * - Upload directory SHOULD be outside the public web root. This is the primary execution
	 *   prevention layer and works on all web servers (Apache, Nginx, Caddy, Swoole, etc.).
	 * - The .htaccess protection written by this class is a secondary defence layer that only
	 *   works on Apache with AllowOverride enabled. It provides NO protection on Nginx, Caddy,
	 *   RoadRunner, Swoole, or any other server. Do not rely on it as your sole protection.
	 */
	class SecureUploadAspect implements BeforeAspectInterface {
		
		/** @var string Base upload directory path */
		private string $uploadPath;
		
		/** @var array<string> Allowed file extensions */
		private array $allowedExtensions;
		
		/** @var array<string> Allowed MIME types */
		private array $allowedMimeTypes;
		
		/** @var int Maximum file size in bytes */
		private int $maxFileSize;
		
		/** @var int Maximum number of files per request */
		private int $maxFiles;
		
		/** @var bool Enable virus scanning if available */
		private bool $virusScan;
		
		/** @var int Maximum image width */
		private int $maxImageWidth;
		
		/** @var int Maximum image width */
		private int $maxImageHeight;
		
		/** @var bool Generate random filenames to prevent conflicts */
		private bool $randomizeFilenames;
		
		/** @var string Directory structure for organizing uploads */
		private string $directoryStructure;
		
		/** @var bool Create directories if they don't exist */
		private bool $createDirectories;
		
		/** @var bool Store original filenames in metadata */
		private bool $preserveOriginalNames;
		
		/** @var bool If true, returns an error response immediately on validation failure instead of writing failure info to request attributes */
		private bool $immediateResponse;
		
		/**
		 * Constructor
		 * @param string $uploadPath Base directory for uploads (relative to project root)
		 * @param array<string> $allowedExtensions Allowed file extensions
		 * @param array<string> $allowedMimeTypes Allowed MIME types
		 * @param int $maxFileSize Maximum file size in bytes
		 * @param int $maxFiles Maximum number of files per request
		 * @param bool $virusScan Enable virus scanning if ClamAV is available
		 * @param int $maxImageWidth Maximum allowed image width
		 * @param int $maxImageHeight Maximum allowed image height
		 * @param bool $randomizeFilenames Generate random filenames
		 * @param string $directoryStructure Directory structure pattern (Y/m/d for date-based)
		 * @param bool $createDirectories Create directories if they don't exist
		 * @param bool $preserveOriginalNames Store original filenames in request attributes
		 * @param bool $immediateResponse If true, returns an error response immediately on validation failure instead of writing failure info to request attributes
		 */
		public function __construct(
			string $uploadPath = 'storage/uploads',
			array  $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'],
			array  $allowedMimeTypes = [
				'image/jpeg', 'image/png', 'image/gif',
				'application/pdf', 'application/msword',
				'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
			],
			int    $maxFileSize = 5242880, // 5MB
			int    $maxFiles = 5,
			bool   $virusScan = false,
			int    $maxImageWidth = 2048,
			int    $maxImageHeight = 2048,
			bool   $randomizeFilenames = true,
			string $directoryStructure = 'Y/m/d',
			bool   $createDirectories = true,
			bool   $preserveOriginalNames = true,
			bool   $immediateResponse = false
		) {
			$this->uploadPath = rtrim($uploadPath, '/');
			$this->allowedExtensions = array_map('strtolower', $allowedExtensions);
			$this->allowedMimeTypes = $allowedMimeTypes;
			$this->maxFileSize = $maxFileSize;
			$this->maxFiles = $maxFiles;
			$this->virusScan = $virusScan;
			$this->maxImageWidth = $maxImageWidth;
			$this->maxImageHeight = $maxImageHeight;
			$this->randomizeFilenames = $randomizeFilenames;
			$this->directoryStructure = $directoryStructure;
			$this->createDirectories = $createDirectories;
			$this->preserveOriginalNames = $preserveOriginalNames;
			$this->immediateResponse = $immediateResponse;
		}
		
		/**
		 * Processes file uploads before the controller method executes
		 * @param MethodContextInterface $context The method execution context
		 * @return Response|null Returns error response if validation fails (in immediateResponse mode), null to continue
		 */
		public function before(MethodContextInterface $context): ?Response {
			// Extract the HTTP request from the method context
			$request = $context->getRequest();
			
			// Get all uploaded files from the request
			// This includes files from all form fields (e.g., $_FILES array contents)
			$files = $request->files->all();
			
			// Check if any files were actually uploaded
			if (empty($files)) {
				// No files present in the request - skip processing
				return null; // No files to process
			}
			
			// Process and validate the uploaded files
			// All errors — batch-level and per-file — are returned in the result, never thrown
			$result = $this->processUploadedFiles($files);
			$processedFiles = $result['files'];
			$batchError = $result['batch_error'];
			$warnings = $result['warnings'];
			
			// Determine overall success: no batch error and every individual file must have passed
			// Controllers can check this flag to confirm all files were handled properly
			$allSuccessful = $batchError === null;
			
			if ($allSuccessful) {
				foreach ($processedFiles as $fieldFiles) {
					foreach ($fieldFiles as $fileResult) {
						if (!$fileResult['success']) {
							$allSuccessful = false;
							break 2;
						}
					}
				}
			}
			
			// Store the processed file information in the request attributes
			// This makes the per-file results (including any errors) available to the controller
			$request->attributes->set('uploaded_files', $processedFiles);
			
			// Set a flag indicating whether all uploads processed successfully
			$request->attributes->set('upload_successful', $allSuccessful);
			
			// Expose the batch-level error so controllers can distinguish failure reasons
			// (e.g. too many files vs. per-file validation failure vs. no files uploaded)
			$request->attributes->set('upload_batch_error', $batchError);
			
			// Expose aggregated warnings so controllers can surface skipped-check notices to users
			$request->attributes->set('upload_warnings', $warnings);
			
			// Return null to indicate the request should continue to the controller
			if ($allSuccessful || !$this->immediateResponse) {
				return null;
			}
			
			// In immediateResponse mode, collect all errors and return a single response
			$errors = [];
			
			// Include the batch-level error first if present (e.g. too many files)
			if ($batchError !== null) {
				$errors[] = $batchError;
			}
			
			foreach ($processedFiles as $fieldName => $fieldFiles) {
				foreach ($fieldFiles as $index => $fileResult) {
					foreach ($fileResult['errors'] as $error) {
						$errors[] = "[{$fieldName}[{$index}]] {$error}";
					}
				}
			}
			
			return $this->createErrorResponse(implode('; ', $errors), $request);
		}
		
		/**
		 * Processes all uploaded files
		 *
		 * Output is normalized: every field always maps to an indexed array of processed
		 * file records, regardless of whether the field accepted one or multiple files.
		 * Each record contains a 'success' flag and an 'errors' array so consumers can
		 * handle partial batch failures without catching exceptions.
		 *
		 * The return value always has three keys:
		 * - 'batch_error': a string if a batch-level check failed (e.g. too many files), null otherwise
		 * - 'warnings':    aggregated, deduplicated warning messages across all files
		 * - 'files':       the per-field, per-file result arrays (empty when batch_error is set)
		 *
		 * @param array<string, UploadedFile|array<int, UploadedFile>> $files Array of uploaded files
		 * @return array{batch_error: string|null, warnings: string[], files: array<string, array<int, array<string, mixed>>>}
		 */
		private function processUploadedFiles(array $files): array {
			// Count total number of files to validate against limits
			$totalFiles = 0;
			
			foreach ($files as $file) {
				$totalFiles += is_array($file) ? count($file) : 1;
			}
			
			// Validate the file count at the batch level before touching any individual file.
			// Reported as a batch_error so the caller never needs to catch an exception.
			if ($totalFiles > $this->maxFiles) {
				return [
					'batch_error' => "Too many files uploaded. Maximum allowed: {$this->maxFiles}",
					'warnings'    => [],
					'files'       => [],
				];
			}
			
			// Initialize array to store processed file information
			$processedFiles = [];
			
			// Process each field containing uploaded files
			foreach ($files as $fieldName => $file) {
				// Always initialize as an indexed array so the return type is uniform.
				// Single-file fields get a one-element array; multi-file fields get N elements.
				// Consumers can always foreach over $result[$field] without type-checking first.
				$processedFiles[$fieldName] = [];
				
				// Normalize single files into an array so both cases share the same processing path
				$fileList = is_array($file) ? $file : [$file];
				
				foreach ($fileList as $singleFile) {
					$validation = $this->collectValidationResult($singleFile);
					
					if (!empty($validation['errors'])) {
						$processedFiles[$fieldName][] = [
							'success'       => false,
							'errors'        => $validation['errors'],
							'warnings'      => $validation['warnings'],
							'original_name' => $this->preserveOriginalNames ? $singleFile->getClientOriginalName() : null,
						];
						continue;
					}
					
					// Validation passed — attempt to move the file to permanent storage
					$fileResult = $this->processSingleFile($singleFile);
					$fileResult['warnings'] = $validation['warnings'];
					$processedFiles[$fieldName][] = $fileResult;
				}
			}
			
			// Aggregate all per-file warnings into a top-level list for quick inspection
			$allWarnings = [];
			
			foreach ($processedFiles as $fieldFiles) {
				foreach ($fieldFiles as $fileResult) {
					foreach ($fileResult['warnings'] as $warning) {
						$allWarnings[] = $warning;
					}
				}
			}
			
			// Return the array of all processed file information
			return [
				'batch_error' => null,
				'warnings'    => array_values(array_unique($allWarnings)),
				'files'       => $processedFiles,
			];
		}
		
		/**
		 * Checks whether the uploaded file is an image based on its MIME type
		 * @param UploadedFile $file The uploaded file
		 * @return bool True if the file is an image
		 */
		private function isImage(UploadedFile $file): bool {
			return str_starts_with((string)$file->getMimeType(), 'image/');
		}
		
		/**
		 * Runs all validation checks against a file and returns every error and warning found.
		 * This method never throws — each validator returns a string on failure or null on success.
		 * Warnings indicate checks that were requested but could not be performed (e.g. ClamAV not installed).
		 *
		 * @param UploadedFile $file The uploaded file to validate
		 * @return array{errors: array<int, string>, warnings: array<int, string>}
		 */
		private function collectValidationResult(UploadedFile $file): array {
			if (!$file->isValid()) {
				// A PHP upload error means the file itself is broken; no further checks make sense
				return [
					'errors'   => [$this->getUploadErrorMessage($file->getError())],
					'warnings' => [],
				];
			}
			
			$errors = [
				$this->validateFileSize($file),
				$this->validateFileType($file),
				$this->validateFileName($file),
			];
			
			// Image-specific validators only run when the file is actually an image
			// Running getimagesize() on PDFs or DOCX files returns false, causing false positives
			if ($this->isImage($file)) {
				$errors[] = $this->validateImageContent($file);
				$errors[] = $this->validateImageDimensions($file);
			}
			
			// Virus scan returns both an error and a warning channel
			$virusScanResult = $this->scanForViruses($file);
			$errors[] = $virusScanResult['error'];
			$warnings = array_values(array_filter([$virusScanResult['warning']]));
			
			return [
				'errors'   => array_values(array_filter($errors)),
				'warnings' => $warnings,
			];
		}
		
		/**
		 * Moves a validated file to permanent storage and returns its metadata.
		 * Validation is intentionally absent here — callers must run collectValidationErrors()
		 * first and only invoke this method when that returns an empty array.
		 * This method never throws; move and post-move failures are returned in 'errors'.
		 *
		 * @param UploadedFile $file The uploaded file to store (must already be validated)
		 * @return array<string, mixed> File metadata with 'success' flag and 'errors' array
		 */
		private function processSingleFile(UploadedFile $file): array {
			try {
				// Move file from temporary upload location to secure permanent storage
				$targetPath = $this->generateTargetPath($file);           // Generate unique secure file path
				$movedFile = $this->moveUploadedFile($file, $targetPath); // Perform the actual file move
			} catch (\Exception $e) {
				// File move or post-move operations failed (e.g. disk full, permissions)
				// Return a failure result so the batch is not interrupted
				return [
					'success'       => false,
					'errors'        => [$e->getMessage()],
					'warnings'      => [],
					'original_name' => $this->preserveOriginalNames ? $file->getClientOriginalName() : null,
				];
			}
			
			// Return comprehensive file information for database storage and client response
			$relativePath = str_replace(ComposerUtils::getProjectRoot() . '/', '', $movedFile);
			
			return [
				'success'       => true,
				'errors'        => [],
				// Preserve original filename only if configuration allows it
				'original_name' => $this->preserveOriginalNames ? $file->getClientOriginalName() : null,
				'filename'      => basename($movedFile),                 // New filename after processing
				'path'          => $movedFile,                           // Full absolute path to file
				'relative_path' => $relativePath,                        // Path relative to application root
				'size'          => $file->getSize(),                     // File size in bytes
				'mime_type'     => $file->getMimeType(),                 // MIME type for content handling
				'extension'     => $file->getClientOriginalExtension(),  // File extension from original upload
				'uploaded_at'   => date('Y-m-d H:i:s'),                 // Timestamp of successful processing
			];
		}
		
		/**
		 * Validates file size
		 * @param UploadedFile $file The uploaded file
		 * @return string|null Error message, or null if valid
		 */
		private function validateFileSize(UploadedFile $file): ?string {
			if ($file->getSize() > $this->maxFileSize) {
				$maxSizeMB = round($this->maxFileSize / 1024 / 1024, 1);
				return "File too large. Maximum size allowed: {$maxSizeMB}MB";
			}
			
			return null;
		}
		
		/**
		 * Validates file type by extension and MIME type
		 * @param UploadedFile $file The uploaded file
		 * @return string|null Error message, or null if valid
		 */
		private function validateFileType(UploadedFile $file): ?string {
			// Get file extension in lowercase for case-insensitive comparison
			$extension = strtolower($file->getClientOriginalExtension());
			
			// Get the actual MIME type detected by the server
			$mimeType = $file->getMimeType();
			
			// Return an error when the mimetype cannot be determined
			if ($mimeType === null) {
				return "Could not determine file MIME type";
			}
			
			// Check if the file extension is in our whitelist of allowed extensions
			if (!in_array($extension, $this->allowedExtensions, true)) {
				// Create a user-friendly list of allowed extensions for the error message
				$allowed = implode(', ', $this->allowedExtensions);
				return "File extension '{$extension}' not allowed. Allowed types: {$allowed}";
			}
			
			// Verify the MIME type is also allowed (prevents spoofing via filename)
			if (!in_array($mimeType, $this->allowedMimeTypes, true)) {
				return "File type '{$mimeType}' not allowed";
			}
			
			// Additional security layer: ensure the file extension matches the actual content
			// This prevents attacks where someone renames a malicious file (e.g., .exe to .jpg)
			if (!$this->extensionMatchesMimeType($extension, $mimeType)) {
				return "File extension does not match file content";
			}
			
			return null;
		}
		
		/**
		 * Validates filename for security issues
		 * @param UploadedFile $file The uploaded file
		 * @return string|null Error message, or null if valid
		 */
		private function validateFileName(UploadedFile $file): ?string {
			// Get the original filename as provided by the client
			// Note: This comes from user input and should never be trusted
			$filename = $file->getClientOriginalName();
			
			// Check for directory traversal attempts
			// These characters could allow an attacker to escape the intended upload directory
			if (str_contains($filename, '..') || str_contains($filename, '/') || str_contains($filename, '\\')) {
				return "Filename contains invalid characters";
			}
			
			// Check for executable extensions in compound filenames
			// Split filename by dots to examine each part (e.g., "file.php.txt" becomes ["file", "php", "txt"])
			$parts = explode('.', $filename);
			
			// Simple filenames (name + single extension) don't need compound extension checks
			if (count($parts) <= 2) {
				return null;
			}
			
			// List of potentially dangerous executable file extensions
			// These could be executed by the web server if placed in accessible directories
			$dangerousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'pl', 'py', 'jsp', 'asp', 'sh', 'cgi'];
			
			// Check each part of the filename against the dangerous extensions list
			foreach ($parts as $part) {
				// Case-insensitive comparison to catch variations like "PHP", "Php", etc.
				if (in_array(strtolower($part), $dangerousExtensions, true)) {
					return "Filename contains potentially dangerous extension";
				}
			}
			
			return null;
		}
		
		/**
		 * Validates image content and structure
		 * @param UploadedFile $file The uploaded file
		 * @return string|null Error message, or null if valid
		 */
		private function validateImageContent(UploadedFile $file): ?string {
			// Attempt to get image information using getimagesize()
			// The @ symbol suppresses warnings for non-image files
			$imageInfo = @getimagesize($file->getPathname());
			
			// If getimagesize() returns false, the file is not a valid image
			if ($imageInfo === false) {
				return "Invalid image file";
			}
			
			// Check if MIME type from getimagesize matches uploaded MIME type
			// This prevents malicious files with fake extensions or headers
			if ($imageInfo['mime'] !== $file->getMimeType()) {
				return "Image file content does not match declared type";
			}
			
			return null;
		}
		
		/**
		 * Validates image dimensions
		 * @param UploadedFile $file The uploaded file
		 * @return string|null Error message, or null if valid
		 */
		private function validateImageDimensions(UploadedFile $file): ?string {
			// Get image information to check dimensions
			// Using @ to suppress warnings for non-image files
			$imageInfo = @getimagesize($file->getPathname());
			
			// If getimagesize() fails, either the file is not an image
			// or it has already failed validation in validateImageContent()
			if ($imageInfo === false) {
				return null;
			}
			
			// Extract width and height from the image info array
			// getimagesize() returns [width, height, type, attr] format
			[$width, $height] = $imageInfo;
			
			// Check if either dimension exceeds the configured maximum limits
			if ($width > $this->maxImageWidth || $height > $this->maxImageHeight) {
				return "Image dimensions ({$width}x{$height}) exceed maximum allowed ({$this->maxImageWidth}x{$this->maxImageHeight})";
			}
			
			return null;
		}
		
		/**
		 * Scans file for viruses using ClamAV
		 *
		 * Returns an array with two keys:
		 * - 'error':   set when a virus is detected or scanning is critically misconfigured
		 * - 'warning': set when the scan was requested but could not be performed (e.g. ClamAV not installed)
		 *
		 * @param UploadedFile $file The uploaded file
		 * @return array{error: string|null, warning: string|null}
		 */
		private function scanForViruses(UploadedFile $file): array {
			// Do nothing when virusscanning is disabled — not a warning, it's intentional
			if (!$this->virusScan) {
				return ['error' => null, 'warning' => null];
			}
			
			// Check if exec() function is available - it may be disabled for security reasons
			if (!function_exists('exec')) {
				return ['error' => null, 'warning' => 'Virus scan skipped: exec() is disabled'];
			}
			
			// Locate the ClamAV scanner executable on the system
			$clamScanPath = $this->findClamScan();
			
			if (!$clamScanPath) {
				return ['error' => null, 'warning' => 'Virus scan skipped: ClamAV not found'];
			}
			
			// Initialize variables to capture command execution results
			$output = [];      // Will store command output lines
			$returnCode = 0;   // Will store the exit code from clamscan
			
			// Build the command string with proper shell escaping for security
			// escapeshellcmd() prevents command injection on the executable path
			// escapeshellarg() safely wraps the file path to handle special characters
			$command = escapeshellcmd($clamScanPath) . ' ' . escapeshellarg($file->getPathname());
			
			// Execute the ClamAV scan command
			// $output will contain all output lines from clamscan
			// $returnCode will contain the exit status (0=clean, 1=virus found, 2=error)
			exec($command, $output, $returnCode);
			
			// Check if a virus was detected
			// ClamAV returns exit code 1 when malware is found
			if ($returnCode === 1) {
				return ['error' => 'Virus detected in uploaded file', 'warning' => null];
			}
			
			// Note: Exit code 0 means file is clean
			// Exit code 2 would indicate a ClamAV internal error — warn rather than fail
			if ($returnCode === 2) {
				return ['error' => null, 'warning' => 'Virus scan skipped: ClamAV returned an error'];
			}
			
			return ['error' => null, 'warning' => null];
		}
		
		/**
		 * Generates target path for uploaded file
		 * @param UploadedFile $file The uploaded file
		 * @return string Full target path
		 */
		private function generateTargetPath(UploadedFile $file): string {
			$baseDir = ComposerUtils::getProjectRoot() . '/' . $this->uploadPath;
			
			// Generate directory structure
			$targetDir = $this->directoryStructure
				? $baseDir . '/' . date($this->directoryStructure)
				: $baseDir;
			
			// Create directories if needed
			// The !is_dir() check after mkdir() handles the race condition where another process
			// creates the directory between our check and our mkdir() call
			if ($this->createDirectories && !is_dir($targetDir) && !mkdir($targetDir, 0755, true) && !is_dir($targetDir)) {
				throw new RuntimeException("Failed to create upload directory: {$targetDir}");
			}
			
			// Generate filename
			// Extension is lowercased to ensure consistency regardless of what the client sent.
			// Even though the extension was validated earlier, the client may have uploaded ".JPEG"
			// while validation normalised to ".jpeg" — storage must reflect the canonical form.
			$extension = strtolower($file->getClientOriginalExtension());
			$filename = $this->randomizeFilenames
				? bin2hex(random_bytes(16)) . '.' . $extension
				: $this->sanitizeFilename($file->getClientOriginalName());
			
			return $targetDir . '/' . $filename;
		}
		
		/**
		 * Moves uploaded file to target location
		 * @param UploadedFile $file The uploaded file
		 * @param string $targetPath Target file path
		 * @return string Final file path
		 * @throws RuntimeException If move fails
		 */
		private function moveUploadedFile(UploadedFile $file, string $targetPath): string {
			try {
				// Move the uploaded file from temporary location to the target path
				// dirname() gets the directory path, basename() gets the filename
				$file->move(dirname($targetPath), basename($targetPath));
				
				// Set secure file permissions (owner: read/write, group/others: read only)
				// 0644 = rw-r--r-- prevents execution while allowing read access
				// Failure is non-fatal but noted: the file is stored, but permissions may be too permissive
				if (!chmod($targetPath, 0644)) {
					// chmod can legitimately fail on some filesystems (e.g. FAT, network mounts, object storage)
					// Treat as a warning rather than a hard failure — the upload itself succeeded
					trigger_error("SecureUploadAspect: chmod failed on {$targetPath}", E_USER_WARNING);
				}
				
				// Write Apache-specific .htaccess protection to the upload directory.
				// This is a secondary defence — uploads should ideally live outside the web root.
				// Has no effect on Nginx, Caddy, Swoole, or any non-Apache server.
				$this->createHtaccessProtection(dirname($targetPath));
				
				// Return the full path to the successfully moved file
				return $targetPath;
				
			} catch (\Exception $e) {
				// Re-throw any errors as a more specific RuntimeException
				// This provides better error handling context for calling code
				throw new RuntimeException("Failed to move uploaded file: " . $e->getMessage());
			}
		}
		
		/**
		 * Creates .htaccess file to prevent script execution
		 * @param string $directory Directory to protect
		 */
		private function createHtaccessProtection(string $directory): void {
			// Build the full path to the .htaccess file
			$htaccessPath = $directory . '/.htaccess';
			
			// Only create the file if it doesn't already exist to avoid overwriting existing rules
			if (file_exists($htaccessPath)) {
				return;
			}
			
			// Start building the Apache configuration content
			$content = "# Prevent script execution\n";
			
			// Remove handler associations for common script file extensions
			// This tells Apache to stop treating these files as executable scripts
			$content .= "RemoveHandler .php .phtml .php3 .php4 .php5 .pl .py .jsp .asp .sh .cgi\n";
			
			// Remove MIME type associations for the same extensions
			// Double protection by also removing the content-type mappings
			$content .= "RemoveType .php .phtml .php3 .php4 .php5 .pl .py .jsp .asp .sh .cgi\n";
			
			// Create a FilesMatch directive to explicitly deny access to script files
			// This is a third layer of protection using pattern matching
			$content .= "<FilesMatch \"\.(php|phtml|php3|php4|php5|pl|py|jsp|asp|sh|cgi)$\">\n";
			
			// Deny all access to files matching the above pattern
			// This ensures even if handlers/types are somehow restored, access is still blocked
			$content .= "    Deny from all\n";
			$content .= "</FilesMatch>\n";
			
			// Write the protection rules to the .htaccess file
			// Failure here is not silently ignored: if the file cannot be written, uploaded files in
			// this directory may become executable on Apache, which is a security risk
			if (file_put_contents($htaccessPath, $content) === false) {
				throw new RuntimeException("Failed to write .htaccess protection to: {$htaccessPath}");
			}
		}
		
		/**
		 * Checks if file extension matches MIME type
		 *
		 * Each extension maps to an array of accepted MIME types rather than a single value because
		 * MIME detection varies across platforms, OS versions, and server configurations. For example,
		 * JPEG files may be reported as image/jpeg or image/pjpeg depending on the environment.
		 * Using a strict single-value match causes false positives on legitimate uploads.
		 *
		 * @param string $extension File extension
		 * @param string $mimeType MIME type
		 * @return bool True if the MIME type is an accepted match for the extension
		 */
		private function extensionMatchesMimeType(string $extension, string $mimeType): bool {
			// Each extension lists all MIME types that are legitimately produced for that format
			// across different platforms, browsers, and server configurations
			$mimeMap = [
				'jpg'  => ['image/jpeg', 'image/pjpeg'],
				'jpeg' => ['image/jpeg', 'image/pjpeg'],
				'png'  => ['image/png'],
				'gif'  => ['image/gif'],
				'pdf'  => ['application/pdf', 'application/x-pdf'],
				'doc'  => ['application/msword', 'application/vnd.ms-word'],
				'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document',
					'application/zip'], // DOCX is a ZIP container; some detectors report it as such
			];
			
			return isset($mimeMap[$extension]) && in_array($mimeType, $mimeMap[$extension], true);
		}
		
		/**
		 * Sanitizes filename for safe storage
		 * @param string $filename Original filename
		 * @return string Sanitized filename
		 */
		private function sanitizeFilename(string $filename): string {
			// Remove or replace dangerous characters
			$filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename) ?? $filename;
			
			// Prevent multiple dots
			$filename = preg_replace('/\.+/', '.', $filename) ?? $filename;
			
			// Ensure it doesn't start with a dot
			$filename = ltrim($filename, '.');
			
			// Guard against edge cases where sanitization produces an empty string
			// (e.g. a filename consisting entirely of dots or special characters)
			if ($filename === '') {
				$filename = bin2hex(random_bytes(8));
			}
			
			return $filename;
		}
		
		/**
		 * Finds ClamScan executable
		 * @return string|null Path to clamscan or null if not found
		 */
		private function findClamScan(): ?string {
			// shell_exec() may be disabled on hardened servers — cannot resolve PATH-based binaries without it
			if (!function_exists('shell_exec')) {
				return null;
			}
			
			// Define common paths where ClamAV's clamscan executable might be installed
			$paths = ['/usr/bin/clamscan', '/usr/local/bin/clamscan', 'clamscan'];
			
			// Iterate through each potential path
			foreach ($paths as $path) {
				// For absolute paths this correctly identifies the executable.
				// For the bare 'clamscan' entry this will almost always return false because
				// is_executable() does not search PATH — it only checks the literal path relative
				// to cwd. The 'which' fallback below is the only reliable way to resolve bare
				// binary names via PATH.
				if (is_executable($path)) {
					return $path;
				}
				
				// shell_exec() returns string on success, false if the command could not be
				// executed, and null if no output was produced. trim() requires a string, so
				// any non-string result means the binary was not found — skip to the next candidate.
				$output = shell_exec('which ' . escapeshellarg($path) . ' 2>/dev/null');
				
				if (!is_string($output)) {
					// shell_exec() returned false or null — 'which' either failed to run or
					// produced no output, meaning the binary is not on PATH.
					continue;
				}
				
				// 'which' ran successfully — trim whitespace and newlines from the result.
				$which = trim($output);
				
				// If 'which' found the executable and it's actually executable, return the path.
				// The empty-string guard handles the case where 'which' ran but matched nothing.
				if ($which && is_executable($which)) {
					return $which;
				}
			}
			
			// Return null if clamscan executable was not found in any of the attempted locations
			return null;
		}
		
		/**
		 * Gets human-readable upload error message
		 * @param int $error Upload error code
		 * @return string Error message
		 */
		private function getUploadErrorMessage(int $error): string {
			$errors = [
				UPLOAD_ERR_INI_SIZE   => 'File exceeds upload_max_filesize directive',
				UPLOAD_ERR_FORM_SIZE  => 'File exceeds MAX_FILE_SIZE directive',
				UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded',
				UPLOAD_ERR_NO_FILE    => 'No file was uploaded',
				UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
				UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
				UPLOAD_ERR_EXTENSION  => 'Upload stopped by extension'
			];
			
			return $errors[$error] ?? 'Unknown upload error';
		}
		
		/**
		 * Creates appropriate error response
		 * @param string $message Error message
		 * @param Request $request HTTP request
		 * @return Response Error response
		 */
		private function createErrorResponse(string $message, Request $request): Response {
			$contentType = (string)$request->headers->get('Content-Type', '');
			$acceptHeader = (string)$request->headers->get('Accept', '');
			
			if ($request->isXmlHttpRequest() ||
				str_contains($contentType, 'application/json') ||
				str_contains($acceptHeader, 'application/json')) {
				return new JsonResponse([
					'error'   => 'Upload failed',
					'message' => $message
				], 422);
			}
			
			// For regular form submissions, you might want to redirect or render an error page
			// This is a simple implementation - customize based on your needs
			return new Response($message, 422);
		}
	}