<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Runner;
	
	use Psr\Log\LoggerInterface;
	use Quellabs\Contracts\TaskScheduler\TaskException;
	use Quellabs\Contracts\TaskScheduler\TaskInterface;
	use Quellabs\Contracts\TaskScheduler\TaskTimeoutException;
	use Quellabs\Discover\Discover;
	
	/**
	 * Timeout strategy that runs tasks in separate processes with configurable timeouts.
	 * This strategy isolates task execution by creating temporary PHP scripts that execute
	 * the tasks in separate processes, allowing for proper timeout handling and process
	 * termination when tasks exceed their allocated time.
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
		 * Discovery class
		 * @var Discover
		 */
		private Discover $discover;
		
		/**
		 * Constructor - initializes the strategy with a logger instance.
		 * @param int $timeout Maximum execution time in seconds
		 * @param LoggerInterface $logger Logger for debugging and error reporting
		 */
		public function __construct(int $timeout, LoggerInterface $logger) {
			$this->timeout = $timeout;
			$this->logger = $logger;
			$this->discover = new Discover();
		}
		
		/**
		 * Executes a task with a specified timeout in a separate process.
		 * Creates a temporary script containing the serialized task, starts a new process
		 * to execute it, and monitors the process until completion or timeout.
		 * @param TaskInterface $task The task to execute
		 * @throws TaskTimeoutException If the task exceeds the timeout
		 * @throws TaskException If the task fails to execute or start
		 */
		public function run(TaskInterface $task): void {
			// Create a temporary PHP script containing the task
			$tempScript = $this->createTaskScript($task);
			
			try {
				// Start the task process and get process handles
				$processData = $this->startTaskProcess($tempScript, $task->getName());
				
				// Monitor the process until completion or timeout
				$this->monitorProcess($processData, $task->getName());
			} finally {
				// Clean up the temporary script file
				@unlink($tempScript);
			}
		}
		
		/**
		 * Creates a temporary PHP script that executes the given task.
		 * The script contains the serialized task and handles its execution,
		 * including proper error handling and exit codes.
		 * @param TaskInterface $task The task to serialize into the script
		 * @return string Path to the created temporary script
		 */
		private function createTaskScript(TaskInterface $task): string {
			// Determine the autoload-directory (composer)
			$autoloadPath = $this->discover->getProjectRoot() . "/vendor/autoload.php";
			
			// Create a temporary file for the script
			$tempScript = tempnam(sys_get_temp_dir(), 'task_');
			
			// Serialize and encode the task for safe inclusion in the script
			$serializedTask = base64_encode(serialize($task));
			
			// Generate the PHP script content
			$scriptContent = <<<PHP
<?php
	require_once '$autoloadPath';
	
	try {
	    // Deserialize and execute the task
	    \$task = unserialize(base64_decode('{$serializedTask}'));
	    \$task->handle();
	    exit(0); // Success exit code
	} catch (Exception \$e) {
	    // Write error to stderr and exit with failure code
	    fwrite(STDERR, \$e->getMessage() . PHP_EOL);
	    exit(1);
	}
PHP;
			
			// Write the script content to the temporary file
			file_put_contents($tempScript, $scriptContent);
			return $tempScript;
		}
		
		/**
		 * Starts a new process to execute the task script.
		 * Creates a subprocess with proper input/output pipes for communication and monitoring.
		 * @param string $script Path to the script to execute
		 * @param string $taskName Name of the task for error reporting
		 * @return array Array containing the process resource and pipe handles
		 * @throws TaskException If the process fails to start
		 */
		private function startTaskProcess(string $script, string $taskName): array {
			// Build the command to execute the script
			$command = escapeshellcmd(PHP_BINARY) . ' ' . escapeshellarg($script);
			
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
				throw new TaskException("Failed to start subprocess for task {$taskName}");
			}
			
			// Close stdin pipe as we don't need to write to the process
			fclose($pipes[0]);
			
			// Set stdout and stderr to non-blocking mode for monitoring
			stream_set_blocking($pipes[1], false);
			stream_set_blocking($pipes[2], false);
			
			// Return $process and $pipes
			return [
				'process' => $process,
				'pipes'   => $pipes
			];
		}
		
		/**
		 * Monitors the running process and handles timeout enforcement.
		 * Continuously checks the process status and reads output streams
		 * while enforcing the timeout constraint.
		 * @param array $processData Array containing process resource and pipes
		 * @param string $taskName Name of the task for logging and error reporting
		 * @throws TaskTimeoutException|TaskException If the process exceeds the timeout
		 */
		private function monitorProcess(array $processData, string $taskName): void {
			// Fetch process and pipe data
			$process = $processData["process"];
			$pipes = $processData["pipes"];
			
			// Track execution time
			$startTime = time();
			$output = '';
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
					$this->terminateProcess($process, $taskName);
					throw new TaskTimeoutException("Task {$taskName} timed out after {$this->timeout} seconds");
				}
				
				// Read available output from stdout and stderr
				$output .= stream_get_contents($pipes[1]);
				$errorOutput .= stream_get_contents($pipes[2]);
				
				// Sleep briefly to prevent excessive CPU usage
				usleep(100000); // 100ms
			}
			
			// Handle process completion
			$this->handleProcessCompletion($process, $pipes, $taskName, $output, $errorOutput);
		}
		
		/**
		 * Terminates a running process, first attempting graceful termination.
		 * Sends SIGTERM first, then SIGKILL if the process doesn't terminate
		 * within a reasonable time.
		 * @param resource $process The process resource to terminate
		 * @param string $taskName Name of the task for logging
		 */
		private function terminateProcess($process, string $taskName): void {
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
		 * @param array $pipes Array of pipe handles
		 * @param string $taskName Name of the task for logging
		 * @param string $output Stdout output collected during execution
		 * @param string $errorOutput Stderr output collected during execution
		 * @throws TaskException If the process exited with a non-zero code
		 */
		private function handleProcessCompletion($process, array $pipes, string $taskName, string $output, string $errorOutput): void {
			// Read any remaining output from the pipes
			$output .= stream_get_contents($pipes[1]);
			$errorOutput .= stream_get_contents($pipes[2]);
			
			// Close the pipes
			fclose($pipes[1]);
			fclose($pipes[2]);
			
			// Get the exit code and close the process
			$exitCode = proc_close($process);
			
			// Log any output for debugging
			if (!empty($output)) {
				$this->logger->debug("Task {$taskName} output: {$output}");
			}
			
			// Check for failure exit code
			if ($exitCode !== 0) {
				$errorMessage = !empty($errorOutput) ? $errorOutput : "Task exited with code {$exitCode}";
				throw new TaskException("Task {$taskName} failed: {$errorMessage}");
			}
		}
	}