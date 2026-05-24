<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Cron\Runner;
	
	use Psr\Log\LoggerInterface;
	use Quellabs\Canvas\TaskScheduler\JobInterface;
	use Quellabs\Contracts\TaskScheduler\TaskException;
	use Quellabs\Contracts\TaskScheduler\TaskTimeoutException;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * Runner strategy that executes jobs in separate processes with configurable timeouts.
	 * Isolates job execution by creating temporary PHP scripts that run in separate
	 * processes, allowing for proper timeout handling and process termination when
	 * jobs exceed their allocated time.
	 */
	class StrategyTimeout implements TaskRunnerInterface {
		
		/**
		 * @var int Maximum execution time in seconds
		 */
		private int $timeout;
		
		/**
		 * Logger instance for recording timeout events and errors
		 * @var LoggerInterface
		 */
		private LoggerInterface $logger;
		
		/**
		 * Constructor - initializes the strategy with a timeout and logger instance.
		 * @param int $timeout Maximum execution time in seconds
		 * @param LoggerInterface $logger Logger for debugging and error reporting
		 */
		public function __construct(int $timeout, LoggerInterface $logger) {
			$this->timeout = $timeout;
			$this->logger  = $logger;
		}
		
		/**
		 * Executes a job with a specified timeout in a separate process.
		 * Creates a temporary script containing the serialized job, starts a new process
		 * to execute it, and monitors the process until completion or timeout.
		 * @param JobInterface $job The job to execute
		 * @throws TaskTimeoutException If the job exceeds the timeout
		 * @throws TaskException If the job fails to execute or start
		 */
		public function run(JobInterface $job): void {
			// Create a temporary PHP script containing the job
			$tempScript = $this->createJobScript($job);
			
			try {
				// Start the job process and get process handles
				$processData = $this->startJobProcess($tempScript, get_class($job));
				
				// Monitor the process until completion or timeout
				$this->monitorProcess($processData, get_class($job));
			} finally {
				// Clean up the temporary script file
				@unlink($tempScript);
			}
		}
		
		/**
		 * Creates a temporary PHP script that executes the given job.
		 * The script contains the serialized job and handles its execution,
		 * including proper error handling and exit codes.
		 * @param JobInterface $job The job to serialize into the script
		 * @return string Path to the created temporary script
		 */
		private function createJobScript(JobInterface $job): string {
			// Determine the autoload-directory (composer)
			$autoloadPath = ComposerUtils::getProjectRoot() . "/vendor/autoload.php";
			
			// Create a temporary file for the script
			$tempScript = tempnam(sys_get_temp_dir(), 'job_');
			
			// Serialize and encode the job for safe inclusion in the script
			$serializedJob = base64_encode(serialize($job));
			
			// Generate the PHP script content
			$scriptContent = <<<PHP
<?php
	require_once '$autoloadPath';

	try {
	    // Deserialize and execute the job
	    \$job = unserialize(base64_decode('{$serializedJob}'));
	    \$job->handle();
	    exit(0); // Success exit code
	} catch (Exception \$e) {
	    // Write error to stderr and exit with failure code
	    fwrite(STDERR, $e->getMessage() . PHP_EOL);
	    exit(1);
	}
PHP;
			
			// Write the script content to the temporary file
			file_put_contents($tempScript, $scriptContent);
			return $tempScript;
		}
		
		/**
		 * Starts a new process to execute the job script.
		 * Creates a subprocess with proper input/output pipes for communication and monitoring.
		 * @param string $script Path to the script to execute
		 * @param string $jobClass Class name of the job for error reporting
		 * @return array{process: resource, pipes: array<int, resource>} Array containing the process resource and pipe handles
		 * @throws TaskException If the process fails to start
		 */
		private function startJobProcess(string $script, string $jobClass): array {
			// Build the command to execute the script
			$command = escapeshellcmd(PHP_BINARY) . ' StrategyTimeout.php' . escapeshellarg($script);
			
			// Define pipe descriptors for stdin, stdout, and stderr
			$descriptors = [
				0 => ['pipe', 'r'], // stdin
				1 => ['pipe', 'w'], // stdout
				2 => ['pipe', 'w']  // stderr
			];
			
			// Start the process
			$process = proc_open($command, $descriptors, $pipes);
			
			// Check if process creation was successful
			if (!is_resource($process)) {
				throw new TaskException("Failed to start subprocess for job {$jobClass}");
			}
			
			// Close stdin pipe as we don't need to write to the process
			fclose($pipes[0]);
			
			// Set stdout and stderr to non-blocking mode for monitoring
			stream_set_blocking($pipes[1], false);
			stream_set_blocking($pipes[2], false);
			
			return [
				'process' => $process,
				'pipes'   => $pipes
			];
		}
		
		/**
		 * Monitors the running process and handles timeout enforcement.
		 * Continuously checks the process status and reads output streams
		 * while enforcing the timeout constraint.
		 * @param array{process: resource, pipes: array<int, resource>} $processData Array containing process resource and pipes
		 * @param string $jobClass Class name of the job for logging and error reporting
		 * @throws TaskTimeoutException|TaskException If the process exceeds the timeout
		 */
		private function monitorProcess(array $processData, string $jobClass): void {
			// Fetch process and pipe data
			$process = $processData["process"];
			$pipes   = $processData["pipes"];
			
			// Track execution time
			$startTime   = time();
			$output      = '';
			$errorOutput = '';
			
			// Monitor loop
			while (true) {
				// Check if the process is still running
				$status = proc_get_status($process);
				
				if ($status['running'] === false) {
					break; // The process has finished
				}
				
				// Check for timeout
				if (time() - $startTime >= $this->timeout) {
					$this->terminateProcess($process, $jobClass);
					throw new TaskTimeoutException("Job {$jobClass} timed out after {$this->timeout} seconds");
				}
				
				// Read available output from stdout and stderr
				$output      .= stream_get_contents($pipes[1]);
				$errorOutput .= stream_get_contents($pipes[2]);
				
				// Sleep briefly to prevent excessive CPU usage
				usleep(100000); // 100ms
			}
			
			// Handle process completion
			$this->handleProcessCompletion($process, $pipes, $jobClass, $output, $errorOutput);
		}
		
		/**
		 * Terminates a running process, first attempting graceful termination.
		 * Sends SIGTERM first, then SIGKILL if the process doesn't terminate
		 * within a reasonable time.
		 * @param resource $process The process resource to terminate
		 * @param string $jobClass Class name of the job for logging
		 */
		private function terminateProcess($process, string $jobClass): void {
			// Attempt graceful termination first
			proc_terminate($process, SIGTERM);
			sleep(1); // Give process time to clean up
			
			// Check if the process is still running
			$status = proc_get_status($process);
			
			// Force kill if still running
			if ($status['running']) {
				proc_terminate($process, SIGKILL);
			}
		}
		
		/**
		 * Handles the completion of a process execution.
		 * @param resource $process The completed process resource
		 * @param array<int, resource> $pipes Array of pipe handles
		 * @param string $jobClass Class name of the job for logging
		 * @param string $output Stdout output collected during execution
		 * @param string $errorOutput Stderr output collected during execution
		 * @throws TaskException If the process exited with a non-zero code
		 */
		private function handleProcessCompletion($process, array $pipes, string $jobClass, string $output, string $errorOutput): void {
			// Read any remaining output from the pipes
			$output      .= stream_get_contents($pipes[1]);
			$errorOutput .= stream_get_contents($pipes[2]);
			
			// Close the pipes
			fclose($pipes[1]);
			fclose($pipes[2]);
			
			// Get the exit code and close the process
			$exitCode = proc_close($process);
			
			// Log any output for debugging
			if (!empty($output)) {
				$this->logger->debug("Job {$jobClass} output: {$output}");
			}
			
			// Check for failure exit code
			if ($exitCode !== 0) {
				$errorMessage = !empty($errorOutput) ? $errorOutput : "Job exited with code {$exitCode}";
				throw new TaskException("Job {$jobClass} failed: {$errorMessage}");
			}
		}
	}
