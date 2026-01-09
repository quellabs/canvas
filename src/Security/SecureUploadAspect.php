<?php
	
	namespace Quellabs\Canvas\Security;
	
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\File\UploadedFile;
	use Symfony\Component\HttpFoundation\JsonResponse;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
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
	 * - Safe storage location outside web root
	 * - Content validation for image files
	 * - Execution prevention for uploaded files
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
		
		/** @var bool Validate image dimensions and content */
		private bool $validateImages;
		
		/** @var array<string,int> Maximum image dimensions [width, height] */
		private array $maxImageDimensions;
		
		/** @var bool Generate random filenames to prevent conflicts */
		private bool $randomizeFilenames;
		
		/** @var string Directory structure for organizing uploads */
		private string $directoryStructure;
		
		/** @var bool Create directories if they don't exist */
		private bool $createDirectories;
		
		/** @var bool Store original filenames in metadata */
		private bool $preserveOriginalNames;
		
		/**
		 * Constructor
		 * @param string $uploadPath Base directory for uploads (relative to project root)
		 * @param array<string> $allowedExtensions Allowed file extensions
		 * @param array<string> $allowedMimeTypes Allowed MIME types
		 * @param int $maxFileSize Maximum file size in bytes
		 * @param int $maxFiles Maximum number of files per request
		 * @param bool $virusScan Enable virus scanning if ClamAV is available
		 * @param bool $validateImages Validate image content and dimensions
		 * @param array<string,int> $maxImageDimensions Maximum image dimensions [width, height]
		 * @param bool $randomizeFilenames Generate random filenames
		 * @param string $directoryStructure Directory structure pattern (Y/m/d for date-based)
		 * @param bool $createDirectories Create directories if they don't exist
		 * @param bool $preserveOriginalNames Store original filenames in request attributes
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
			bool   $validateImages = true,
			array  $maxImageDimensions = ['width' => 2048, 'height' => 2048],
			bool   $randomizeFilenames = true,
			string $directoryStructure = 'Y/m/d',
			bool   $createDirectories = true,
			bool   $preserveOriginalNames = true
		) {
			$this->uploadPath = rtrim($uploadPath, '/');
			$this->allowedExtensions = array_map('strtolower', $allowedExtensions);
			$this->allowedMimeTypes = $allowedMimeTypes;
			$this->maxFileSize = $maxFileSize;
			$this->maxFiles = $maxFiles;
			$this->virusScan = $virusScan;
			$this->validateImages = $validateImages;
			$this->maxImageDimensions = $maxImageDimensions;
			$this->randomizeFilenames = $randomizeFilenames;
			$this->directoryStructure = $directoryStructure;
			$this->createDirectories = $createDirectories;
			$this->preserveOriginalNames = $preserveOriginalNames;
		}
		
		/**
		 * Processes file uploads before the controller method executes
		 * @param MethodContext $context The method execution context
		 * @return Response|null Returns error response if validation fails, null to continue
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
			
			try {
				// Process and validate the uploaded files
				// This method likely handles file validation, moving files to permanent storage,
				// generating file metadata, and performing security checks
				$processedFiles = $this->processUploadedFiles($files);
				
				// Store the processed file information in the request attributes
				// This makes the file data available to the controller method
				$request->attributes->set('uploaded_files', $processedFiles);
				
				// Set a flag indicating successful upload processing
				// Controllers can check this to confirm files were handled properly
				$request->attributes->set('upload_successful', true);
				
				// Return null to indicate the request should continue to the controller
				return null;
				
			} catch (RuntimeException $e) {
				// Handle any errors that occurred during file processing
				// This could include validation failures, storage issues, or security violations
				// Return an error response instead of continuing to the controller
				return $this->createErrorResponse($e->getMessage(), $request);
			}
		}
		
		/**
		 * Processes all uploaded files
		 * @param array $files Array of uploaded files
		 * @return array<string,array> Processed file information
		 * @throws RuntimeException If validation fails
		 */
		private function processUploadedFiles(array $files): array {
			// Initialize array to store processed file information
			$processedFiles = [];
			
			// Count total number of files to validate against limits
			$totalFiles = $this->countFiles($files);
			
			// Validate that the number of uploaded files doesn't exceed the maximum allowed
			if ($totalFiles > $this->maxFiles) {
				throw new RuntimeException("Too many files uploaded. Maximum allowed: {$this->maxFiles}");
			}
			
			// Process each field containing uploaded files
			foreach ($files as $fieldName => $file) {
				// Single file upload - process directly
				if (!is_array($file)) {
					$processedFiles[$fieldName] = $this->processSingleFile($file);
					continue;
				}
				
				// Initialize array for this field's processed files
				$processedFiles[$fieldName] = [];
				
				// Process each individual file in the array
				foreach ($file as $index => $singleFile) {
					$processedFiles[$fieldName][$index] = $this->processSingleFile($singleFile);
				}
			}
			
			// Return the array of all processed file information
			return $processedFiles;
		}
		
		/**
		 * Processes a single uploaded file through validation, security checks, and storage
		 * @param UploadedFile $file The uploaded file to process
		 * @return array File information including paths, metadata, and upload timestamp
		 * @throws RuntimeException If validation fails or file processing encounters errors
		 */
		private function processSingleFile(UploadedFile $file): array {
			// Check if the file upload completed successfully without errors
			if (!$file->isValid()) {
				throw new RuntimeException("File upload error: " . $this->getUploadErrorMessage($file->getError()));
			}
			
			// Perform basic security and business rule validations
			$this->validateFileSize($file);      // Check file doesn't exceed size limits
			$this->validateFileType($file);      // Ensure file type is in allowed list
			$this->validateFileName($file);      // Sanitize filename for security
			
			// Additional validation for image files if image processing is enabled
			if ($this->isImage($file) && $this->validateImages) {
				$this->validateImageContent($file);      // Verify actual image content matches extension
				$this->validateImageDimensions($file);   // Check image meets size requirements
			}
			
			// Optional virus scanning for enhanced security
			if ($this->virusScan) {
				$this->scanForViruses($file);    // Scan file for malicious content
			}
			
			// Move file from temporary upload location to secure permanent storage
			$targetPath = $this->generateTargetPath($file);        // Generate unique secure file path
			$movedFile = $this->moveUploadedFile($file, $targetPath);  // Perform the actual file move
			
			// Return comprehensive file information for database storage and client response
			$relativePath = str_replace(getcwd() . '/', '', $movedFile);
			
			return [
				// Preserve original filename only if configuration allows it
				'original_name' => $this->preserveOriginalNames ? $file->getClientOriginalName() : null,
				'filename'      => basename($movedFile),                  // New filename after processing
				'path'          => $movedFile,                            // Full absolute path to file
				'relative_path' => $relativePath,                         // Path relative to application root
				'size'          => $file->getSize(),                      // File size in bytes
				'mime_type'     => $file->getMimeType(),                  // MIME type for content handling
				'extension'     => $file->getClientOriginalExtension(),   // File extension from original upload
				'uploaded_at'   => date('Y-m-d H:i:s')             // Timestamp of successful processing
			];
		}
		
		/**
		 * Validates file size
		 * @param UploadedFile $file The uploaded file
		 * @throws RuntimeException If file is too large
		 */
		private function validateFileSize(UploadedFile $file): void {
			if ($file->getSize() > $this->maxFileSize) {
				$maxSizeMB = round($this->maxFileSize / 1024 / 1024, 1);
				throw new RuntimeException("File too large. Maximum size allowed: {$maxSizeMB}MB");
			}
		}
		
		/**
		 * Validates file type by extension and MIME type
		 * @param UploadedFile $file The uploaded file
		 * @throws RuntimeException If file type is not allowed
		 */
		private function validateFileType(UploadedFile $file): void {
			// Get file extension in lowercase for case-insensitive comparison
			$extension = strtolower($file->getClientOriginalExtension());
			
			// Get the actual MIME type detected by the server
			$mimeType = $file->getMimeType();
			
			// Check if the file extension is in our whitelist of allowed extensions
			if (!in_array($extension, $this->allowedExtensions)) {
				// Create a user-friendly list of allowed extensions for the error message
				$allowed = implode(', ', $this->allowedExtensions);
				throw new RuntimeException("File extension '{$extension}' not allowed. Allowed types: {$allowed}");
			}
			
			// Verify the MIME type is also allowed (prevents spoofing via filename)
			if (!in_array($mimeType, $this->allowedMimeTypes)) {
				throw new RuntimeException("File type '{$mimeType}' not allowed");
			}
			
			// Additional security layer: ensure the file extension matches the actual content
			// This prevents attacks where someone renames a malicious file (e.g., .exe to .jpg)
			if (!$this->extensionMatchesMimeType($extension, $mimeType)) {
				throw new RuntimeException("File extension does not match file content");
			}
		}
		
		/**
		 * Validates filename for security issues
		 * @param UploadedFile $file The uploaded file
		 * @throws RuntimeException If filename is dangerous
		 */
		private function validateFileName(UploadedFile $file): void {
			// Get the original filename as provided by the client
			// Note: This comes from user input and should never be trusted
			$filename = $file->getClientOriginalName();
			
			// Check for directory traversal attempts
			// These characters could allow an attacker to escape the intended upload directory
			if (str_contains($filename, '..') || str_contains($filename, '/') || str_contains($filename, '\\')) {
				throw new RuntimeException("Filename contains invalid characters");
			}
			
			// Check for executable extensions in compound filenames
			// Split filename by dots to examine each part (e.g., "file.php.txt" becomes ["file", "php", "txt"])
			$parts = explode('.', $filename);
			
			// Only check compound filenames (more than 2 parts: name + extension)
			// This prevents files like "malicious.php.txt" from being uploaded
			if (count($parts) > 2) {
				// List of potentially dangerous executable file extensions
				// These could be executed by the web server if placed in accessible directories
				$dangerousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'pl', 'py', 'jsp', 'asp', 'sh', 'cgi'];
				
				// Check each part of the filename against the dangerous extensions list
				foreach ($parts as $part) {
					// Case-insensitive comparison to catch variations like "PHP", "Php", etc.
					if (in_array(strtolower($part), $dangerousExtensions)) {
						throw new RuntimeException("Filename contains potentially dangerous extension");
					}
				}
			}
		}
		
		/**
		 * Validates image content and structure
		 * @param UploadedFile $file The uploaded file
		 * @throws RuntimeException If image is invalid
		 */
		private function validateImageContent(UploadedFile $file): void {
			// Attempt to get image information using getimagesize()
			// The @ symbol suppresses warnings for non-image files
			$imageInfo = @getimagesize($file->getPathname());
			
			// If getimagesize() returns false, the file is not a valid image
			if ($imageInfo === false) {
				throw new RuntimeException("Invalid image file");
			}
			
			// Check if MIME type from getimagesize matches uploaded MIME type
			// This prevents malicious files with fake extensions or headers
			$detectedMime = $imageInfo['mime'];
			if ($detectedMime !== $file->getMimeType()) {
				throw new RuntimeException("Image file content does not match declared type");
			}
		}
		
		/**
		 * Validates image dimensions
		 * @param UploadedFile $file The uploaded file
		 * @throws RuntimeException If image dimensions exceed limits
		 */
		private function validateImageDimensions(UploadedFile $file): void {
			// Get image information to check dimensions
			// Using @ to suppress warnings for non-image files
			$imageInfo = @getimagesize($file->getPathname());
			
			// If getimagesize() fails, either the file is not an image
			// or it has already failed validation in validateImageContent()
			if ($imageInfo === false) {
				return; // Not an image or already failed validation
			}
			
			// Extract width and height from the image info array
			// getimagesize() returns [width, height, type, attr] format
			[$width, $height] = $imageInfo;
			
			// Check if either dimension exceeds the configured maximum limits
			if ($width > $this->maxImageDimensions['width'] || $height > $this->maxImageDimensions['height']) {
				// Get max dimensions for error message
				$maxW = $this->maxImageDimensions['width'];
				$maxH = $this->maxImageDimensions['height'];
				
				// Throw descriptive error with actual vs allowed dimensions
				throw new RuntimeException("Image dimensions ({$width}x{$height}) exceed maximum allowed ({$maxW}x{$maxH})");
			}
		}
		
		/**
		 * Scans file for viruses using ClamAV
		 * @param UploadedFile $file The uploaded file
		 * @throws RuntimeException If virus is detected
		 */
		private function scanForViruses(UploadedFile $file): void {
			// Check if exec() function is available - it may be disabled for security reasons
			if (!function_exists('exec')) {
				return; // Cannot execute virus scan - silently skip scanning
			}
			
			// Locate the ClamAV scanner executable on the system
			$clamscanPath = $this->findClamScan();
			
			if (!$clamscanPath) {
				return;
			}
			
			// Initialize variables to capture command execution results
			$output = [];      // Will store command output lines
			$returnCode = 0;   // Will store the exit code from clamscan
			
			// Build the command string with proper shell escaping for security
			// escapeshellcmd() prevents command injection on the executable path
			// escapeshellarg() safely wraps the file path to handle special characters
			$command = escapeshellcmd($clamscanPath) . ' ' . escapeshellarg($file->getPathname());
			
			// Execute the ClamAV scan command
			// $output will contain all output lines from clamscan
			// $returnCode will contain the exit status (0=clean, 1=virus found, 2=error)
			exec($command, $output, $returnCode);
			
			// Check if a virus was detected
			// ClamAV returns exit code 1 when malware is found
			if ($returnCode === 1) {
				throw new RuntimeException("Virus detected in uploaded file");
			}
			
			// Note: Exit code 0 means file is clean
			// Exit code 2 would indicate an error (not handled here)
			// Method returns void on success (clean file)
		}
		
		/**
		 * Generates target path for uploaded file
		 * @param UploadedFile $file The uploaded file
		 * @return string Full target path
		 */
		private function generateTargetPath(UploadedFile $file): string {
			$baseDir = getcwd() . '/' . $this->uploadPath;
			
			// Generate directory structure
			if ($this->directoryStructure) {
				$subDir = date($this->directoryStructure);
				$targetDir = $baseDir . '/' . $subDir;
			} else {
				$targetDir = $baseDir;
			}
			
			// Create directories if needed
			if ($this->createDirectories && !is_dir($targetDir)) {
				mkdir($targetDir, 0755, true);
			}
			
			// Generate filename
			if ($this->randomizeFilenames) {
				$extension = $file->getClientOriginalExtension();
				$filename = $this->generateRandomFilename() . '.' . $extension;
			} else {
				$filename = $this->sanitizeFilename($file->getClientOriginalName());
			}
			
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
				chmod($targetPath, 0644);
				
				// Create security protection in the target directory to prevent
				// accidental execution of uploaded files if they end up in web-accessible areas
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
			if (!file_exists($htaccessPath)) {
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
				// Using @ to suppress potential file write warnings (errors still thrown as exceptions)
				@file_put_contents($htaccessPath, $content);
			}
		}
		
		/**
		 * Counts total number of files in upload array
		 * @param array $files File array
		 * @return int Total file count
		 */
		private function countFiles(array $files): int {
			// Initialize counter for total files
			$count = 0;
			
			// Iterate through each item in the files array
			foreach ($files as $file) {
				// Check if current item is an array (multiple files for single input)
				// If so, add count of files in this sub-array
				if (is_array($file)) {
					$count += count($file);
				} else {
					$count++;
				}
			}
			
			// Return total count of all files
			return $count;
		}
		
		/**
		 * Checks if file is an image
		 * @param UploadedFile $file The uploaded file
		 * @return bool True if file is an image
		 */
		private function isImage(UploadedFile $file): bool {
			return str_starts_with($file->getMimeType() ?? '', 'image/');
		}
		
		/**
		 * Checks if file extension matches MIME type
		 * @param string $extension File extension
		 * @param string $mimeType MIME type
		 * @return bool True if they match
		 */
		private function extensionMatchesMimeType(string $extension, string $mimeType): bool {
			$mimeMap = [
				'jpg'  => 'image/jpeg',
				'jpeg' => 'image/jpeg',
				'png'  => 'image/png',
				'gif'  => 'image/gif',
				'pdf'  => 'application/pdf',
				'doc'  => 'application/msword',
				'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
			];
			
			return isset($mimeMap[$extension]) && $mimeMap[$extension] === $mimeType;
		}
		
		/**
		 * Generates a random filename
		 * @return string Random filename without extension
		 */
		private function generateRandomFilename(): string {
			return bin2hex(random_bytes(16));
		}
		
		/**
		 * Sanitizes filename for safe storage
		 * @param string $filename Original filename
		 * @return string Sanitized filename
		 */
		private function sanitizeFilename(string $filename): string {
			// Remove or replace dangerous characters
			$filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);
			
			// Prevent multiple dots
			$filename = preg_replace('/\.+/', '.', $filename);
			
			// Ensure it doesn't start with a dot
			return ltrim($filename, '.');
		}
		
		/**
		 * Finds ClamScan executable
		 * @return string|null Path to clamscan or null if not found
		 */
		private function findClamScan(): ?string {
			// Define common paths where ClamAV's clamscan executable might be installed
			$paths = ['/usr/bin/clamscan', '/usr/local/bin/clamscan', 'clamscan'];
			
			// Iterate through each potential path
			foreach ($paths as $path) {
				// Check if the file exists and is executable at this path
				if (is_executable($path)) {
					return $path;
				}
				
				// If direct path check fails, try using the 'which' command to locate the executable
				// The 'which' command searches the PATH environment variable for the executable
				// Redirect stderr to /dev/null to suppress error messages if command not found
				$which = trim(shell_exec("which {$path} 2>/dev/null"));
				
				// If 'which' found the executable and it's actually executable, return the path
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
			$contentType = $request->headers->get('Content-Type', '');
			$acceptHeader = $request->headers->get('Accept', '');
			
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