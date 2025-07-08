<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Sculpt\PublishHelpers\FileOperationManager;
	use Quellabs\Canvas\Sculpt\PublishHelpers\FileOperationException;
	use Quellabs\Canvas\Sculpt\PublishHelpers\FileTransaction;
	use Quellabs\Canvas\Sculpt\PublishHelpers\RollbackException;
	use Quellabs\Contracts\Discovery\ProviderInterface;
	use Quellabs\Contracts\IO\ConsoleInput;
	use Quellabs\Contracts\IO\ConsoleOutput;
	use Quellabs\Discover\Discover;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Quellabs\Discover\Scanner\ComposerScanner;
	use Quellabs\Contracts\Publishing\AssetPublisher;
	
	class PublishCommand extends CommandBase {
		
		/**
		 * @var Discover Discovery component
		 */
		private Discover $discover;
		
		/**
		 * @var FileOperationManager operations manager
		 */
		private FileOperationManager $operationManager;
		
		/**
		 * PublishCommand constructor
		 * @param ConsoleInput $input
		 * @param ConsoleOutput $output
		 * @param ProviderInterface|null $provider
		 */
		public function __construct(ConsoleInput $input, ConsoleOutput $output, ?ProviderInterface $provider = null) {
			parent::__construct($input, $output, $provider);
			$this->discover = new Discover();
			$this->operationManager = new FileOperationManager($output);
		}
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "canvas:publish";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "Publishes assets from available publishers";
		}
		
		/**
		 * Execute the publish command
		 *
		 * This is the main entry point for the canvas:publish command. It handles four scenarios:
		 * 1. --list flag: Shows all available publishers
		 * 2. --help flag: Shows detailed help for a specific tag or general usage
		 * 4. No parameters: Shows usage help
		 *
		 * @param ConfigurationManager $config Configuration containing command flags and options
		 * @return int Exit code (0 = success, 1 = error)
		 */
		public function execute(ConfigurationManager $config): int {
			// Show title of command
			$this->output->writeLn("<info>Canvas Publish Command</info>");
			$this->output->writeLn("");
			
			// Initialize the discovery system to find all available asset publishers
			$discover = new Discover();
			$discover->addScanner(new ComposerScanner("publishers"));
			$discover->discover();
			
			// Retrieve all discovered publisher providers from the discovery system
			$providers = $discover->getProviders();
			
			// Handle the --list flag first (no tag validation needed)
			if ($config->hasFlag("list")) {
				return $this->listPublishers($providers);
			}
			
			// Get the tag parameter once
			$tag = $config->getPositional(0);
			
			// If no tag is provided, show usage help
			if (!$tag) {
				$this->showUsageHelp();
				return 0;
			}
			
			// Validate the tag exists before doing anything else
			if (!$this->findProviderByTag($providers, $tag)) {
				$this->output->error("Publisher with tag '{$tag}' not found.");
				return 1;
			}
			
			// Now that we know the tag is valid, handle help or publish
			if ($config->hasFlag("help")) {
				return $this->showHelp($providers, $tag);
			}
			
			// Proceed with publishing
			return $this->publishTag($providers, $tag, $config->hasFlag("force"), $config->hasFlag("overwrite"));
		}
		
		/**
		 * Show help information for publishers
		 * @param array $providers Array of discovered publisher providers
		 * @param string|null $publisher Optional publisher to show specific help for
		 * @return int Exit code (0 = success, 1 = error)
		 */
		private function showHelp(array $providers, ?string $publisher = null): int {
			// Show help for a specific publisher
			$provider = $this->findProviderByTag($providers, $publisher);
			
			// Display detailed help for the specific publisher
			$this->output->writeLn("<info>Help for publisher: {$publisher}</info>");
			$this->output->writeLn($provider::getDescription());
			$this->output->writeLn("Usage: php ./vendor/bin/sculpt canvas:publish {$publisher}");
			$this->output->writeLn("");
			
			// Show extended help if the publisher supports it
			$helpText = $provider::getHelp();
			
			if (!empty($helpText)) {
				$this->output->writeLn($provider::getHelp());
				$this->output->writeLn("");
			}
			
			return 0;
		}
		
		/**
		 * Find a provider by its tag identifier
		 * @param array $providers Array of provider class names
		 * @param string $tag Tag to search for
		 * @return AssetPublisher|null Provider class if found, null otherwise
		 */
		private function findProviderByTag(array $providers, string $tag): ?AssetPublisher {
			foreach ($providers as $provider) {
				if ($provider::getTag() === $tag) {
					return $provider;
				}
			}
			
			return null;
		}
		
		/**
		 * List all available publishers
		 * @param array $providers
		 * @return int
		 */
		private function listPublishers(array $providers): int {
			$this->output->writeLn("<info>Available Publishers:</info>");
			$this->output->writeLn("");
			
			foreach ($providers as $provider) {
				$this->output->writeLn(sprintf(
					"  <comment>%s</comment> - %s",
					$provider->getTag(),
					$provider->getDescription()
				));
			}
			
			$this->output->writeLn("");
			return 0;
		}
		
		/**
		 * Publish assets for a specific tag with file copying and rollback functionality
		 * @param array $providers
		 * @param string $publisher
		 * @param bool $force
		 * @param bool $overwrite
		 * @return int
		 */
		private function publishTag(array $providers, string $publisher, bool $force = false, bool $overwrite = false): int {
			$targetProvider = $this->findProviderByTag($providers, $publisher);
			
			// Check if the assets can be published
			if (!$targetProvider->canPublish()) {
				$this->showCannotPublishError($targetProvider);
				return 1;
			}
			
			// Validate and prepare for publishing
			$publishData = $this->preparePublishing($targetProvider, $publisher);
			
			if ($publishData === null) {
				return 1; // Error occurred during preparation
			}
			
			// Show preview and get confirmation
			if (!$this->showPublishPreview($publishData, $force, $overwrite)) {
				return 0; // User cancelled
			}
			
			// Execute the publishing process
			return $this->executePublishing($publishData, $targetProvider, $overwrite);
		}
		
		/**
		 * Prepare and validate everything needed for publishing
		 * @param AssetPublisher $targetProvider
		 * @param string $publisher
		 * @return array|null Returns publish data array or null on error
		 */
		private function preparePublishing(AssetPublisher $targetProvider, string $publisher): ?array {
			// Get project root and source directory
			$projectRoot = $this->discover->getProjectRoot();
			
			// Resolve the source directory
			$sourceDirectory = $this->discover->resolvePath($targetProvider->getSourcePath());
			
			// Show information about what we're publishing
			$this->output->writeLn("Publishing: " . $publisher);
			$this->output->writeLn("Description: " . $targetProvider::getDescription());
			$this->output->writeLn("Source directory: " . $sourceDirectory);
			$this->output->writeLn("");
			
			// Get the manifest and validate it
			$manifest = $targetProvider->getManifest();
			
			if (!isset($manifest['files']) || !is_array($manifest['files'])) {
				$this->output->error("Invalid manifest: 'files' key not found or not an array");
				return null;
			}
			
			// Make source path absolute if it's relative
			if (!$this->isAbsolutePath($sourceDirectory)) {
				$sourceDirectory = rtrim($projectRoot, '/') . '/' . ltrim($sourceDirectory, '/');
			}
			
			// Validate source directory exists
			if (!is_dir($sourceDirectory)) {
				$this->output->error("Source directory does not exist: {$sourceDirectory}");
				return null;
			}
			
			return [
				'tag'             => $targetProvider->getTag(),
				'manifest'        => $manifest,
				'publisher'       => $publisher,
				'projectRoot'     => $projectRoot,
				'sourceDirectory' => $this->discover->resolvePath($sourceDirectory)
			];
		}
		
		/**
		 * Show preview of files to be published and get user confirmation
		 * @param array $publishData
		 * @param bool $force
		 * @param bool $overwrite
		 * @return bool True to proceed, false to cancel
		 */
		private function showPublishPreview(array $publishData, bool $force, bool $overwrite): bool {
			// Create a transaction so we can show what it's going to do
			try {
				$transaction = $this->operationManager->createTransaction($publishData, $overwrite);
				
				// Show what it's going to do
				$this->operationManager->previewTransaction($transaction);
				
				// Get user confirmation
				return $this->getUserConfirmation($force);
			} catch (FileOperationException $e) {
				echo $e->getMessage();
				return false;
			}
		}

		/**
		 * Get user confirmation to proceed with publishing
		 * @param bool $force
		 * @return bool True to proceed, false to cancel
		 */
		private function getUserConfirmation(bool $force): bool {
			if ($force) {
				$this->output->writeLn("Force flag set, proceeding without confirmation...");
				return true;
			}
			
			return $this->askForConfirmation();
		}
		
		/**
		 * Execute the actual publishing process with rollback support
		 * @param array $publishData
		 * @param AssetPublisher $targetProvider
		 * @param bool $overwrite
		 * @return int Exit code (0 = success, 1 = error)
		 */
		private function executePublishing(array $publishData, AssetPublisher $targetProvider, bool $overwrite): int {
			// Initialize a new publishing transaction to track all operations
			$transaction = $this->createPublishingTransaction($publishData, $overwrite);
			
			// If no transaction was created (nothing to publish), exit successfully
			if ($transaction === null) {
				return 0;
			}
			
			try {
				// Notify user that the transaction is being committed
				$this->output->writeLn("<info>Committing transaction: {$transaction->getId()}</info>");
				
				// Execute all planned file operations (copy, move, delete, etc.)
				// This is where the actual file system changes happen
				$this->operationManager->commit($transaction);
				
				// Report successful completion with actual operation count
				$operationCount = count($transaction->getExecutedOperations());
				$this->output->writeLn("");
				$this->output->writeLn("<info>Successfully committed transaction: {$transaction->getId()} ({$operationCount} operations)</info>");
				
				// Display any post-publishing instructions from the target provider
				// (e.g., cache clearing, CDN invalidation, etc.)
				$publishInstructions = $targetProvider->getPostPublishInstructions();
				
				if (!empty($publishInstructions)) {
					$this->output->writeLn("");
					$this->output->writeLn($publishInstructions);
				}
				
				// Return success exit code
				return 0;
				
			} catch (FileOperationException $e) {
				// Handle file operation failures by attempting rollback
				$this->output->writeLn("<comment>Rolling back transaction: {$transaction->getId()}</comment>");
				
				// Attempt to undo all committed operations
				try {
					$this->operationManager->rollback($transaction);
					$this->output->writeLn("<info>Transaction rollback completed successfully</info>");
				} catch (RollbackException $e) {
					// If rollback fails, display detailed error information
					$this->output->writeLn("Failed to rollback operation.");
					
					// Show each specific rollback error for debugging
					foreach ($e->getErrors() as $error) {
						$this->output->writeLn("  * " . $error);
					}
				}
				
				// Return error exit code to indicate failure
				return 1;
			}
		}
		
		/**
		 * Creates a file publishing transaction with the provided data.
		 * @param array $publishData The data required for publishing operations
		 * @param bool $overwrite Whether to overwrite existing files during publishing
		 * @return FileTransaction|null Returns the created transaction or null if creation fails
		 */
		private function createPublishingTransaction(array $publishData, bool $overwrite): ?FileTransaction {
			try {
				// Create a new transaction using the operation manager with publish data, overwrite flag, and tag
				$transaction = $this->operationManager->createTransaction($publishData, $overwrite, $publishData['tag']);
				
				// Get the count of planned operations for logging purposes
				$plannedCount = count($transaction->getPlannedOperations());
				
				// Output success message with transaction ID and operation count
				$this->output->writeLn("<info>Created transaction: {$transaction->getId()} with {$plannedCount} planned operations</info>");
				
				return $transaction;
			} catch (FileOperationException $e) {
				// Show an error message
				$this->output->error("Failed creating transaction: {$e->getMessage()}");
				
				// Return null if transaction creation fails due to file operation issues
				// Note: Exception is caught but not logged - consider adding error logging if needed
				return null;
			}
		}
		
		/**
		 * Check if a path is absolute
		 * @param string $path
		 * @return bool
		 */
		private function isAbsolutePath(string $path): bool {
			return $path[0] === '/' || (strlen($path) > 1 && $path[1] === ':');
		}

		/**
		 * Display comprehensive usage help for the canvas:publish command
		 * @return void
		 */
		private function showUsageHelp(): void {
			$this->output->writeLn("<comment>Use publish to add assets using configured publishers</comment>");
			$this->output->writeLn("");
			
			$this->output->writeLn("<info>USAGE:</info>");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish [publisher] [options]");
			$this->output->writeLn("");
			
			$this->output->writeLn("<info>ARGUMENTS:</info>");
			$this->output->writeLn("  <comment>publisher</comment>            Name of the publisher to use");
			$this->output->writeLn("");
			
			$this->output->writeLn("<info>OPTIONS:</info>");
			$this->output->writeLn("  <comment>--list</comment>              List all available publishers");
			$this->output->writeLn("  <comment>--force</comment>             Skip all interactive prompts and confirmations");
			$this->output->writeLn("  <comment>--overwrite</comment>         Overwrite existing files (creates backups)");
			$this->output->writeLn("  <comment>--help</comment>              Display help for a specific publisher or general help");
			$this->output->writeLn("");
			
			$this->output->writeLn("<info>NOTE:</info>");
			$this->output->writeLn("  By default, existing files are skipped. Use --overwrite to replace them.");
			$this->output->writeLn("");
			
			$this->output->writeLn("<info>EXAMPLES:</info>");
			$this->output->writeLn("  <comment># List all available publishers</comment>");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish --list");
			$this->output->writeLn("");
			$this->output->writeLn("  <comment># Publish new files only (skip existing)</comment>");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish production");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish staging");
			$this->output->writeLn("");
			$this->output->writeLn("  <comment># Publish and overwrite existing files</comment>");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish production --overwrite");
			$this->output->writeLn("");
			$this->output->writeLn("  <comment># Skip interactive prompts (non-interactive mode)</comment>");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish production --force");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish production --overwrite --force");
			$this->output->writeLn("");
			$this->output->writeLn("  <comment># Show help information</comment>");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish");
			$this->output->writeLn("  php ./vendor/bin/sculpt canvas:publish production --help");
		}
		
		/**
		 * Displays an error message when asset publishing fails
		 * @param AssetPublisher $targetProvider The asset publisher that failed to publish
		 * @return void
		 */
		private function showCannotPublishError(AssetPublisher $targetProvider): void {
			// Display the main error message to the user
			$this->output->error("Cannot publish assets");
			
			// Display the specific reason why publishing failed, obtained from the target provider
			$this->output->error($targetProvider->getCannotPublishReason());
		}
		
		/**
		 * Prompts the user for confirmation before proceeding with an action.
		 * @return bool Returns true if user confirms with 'y', false otherwise.
		 */
		private function askForConfirmation(): bool {
			// Ask for confirmation
			$confirmation = $this->input->ask("Proceed? (y/N)");
			
			// Check if the user entered 'y' (case-insensitive)
			if ($confirmation && strtolower($confirmation) === 'y') {
				return true; // User confirmed - proceed with the action
			}
			
			// Any input other than 'y' is treated as cancellation
			$this->output->writeLn("Cancelled.");
			
			// User canceled or provided invalid input
			return false;
		}
	}