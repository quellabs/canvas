<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	use Random\RandomException;
	use Quellabs\Canvas\Exceptions\RateLimitStoreUnavailableException;
	use Quellabs\Support\ComposerUtils;

	/**
	 * File-backed rate limit store that holds a single exclusive lock across the
	 * entire read-decide-write cycle for a key, so a concurrent request for the
	 * same key blocks until the first is fully committed instead of racing it.
	 *
	 * One state file per key (fixed-window instance, sliding-window key, or
	 * bucket key); the lock is held on that same file handle for the whole
	 * operation.
	 *
	 * Known limitation: if a key's very first write fails completely (no bytes land), the
	 * resulting empty file is indistinguishable from a never-written key, so readState()
	 * admits again instead of failing closed - accepted as-is, since nothing short of a
	 * successful write can record that the attempt happened.
	 */
	class FileRateLimitStore implements RateLimitStoreInterface {

		/** @var int Seconds after which an untouched state file is considered garbage, not an active window */
		private const int DEFAULT_STALE_AFTER_SECONDS = 86400;

		/** @var int Sweep roughly 1 in this many admission calls, instead of running a cron */
		private const int GC_PROBABILITY = 500;

		/** @var string Directory holding one state file per rate limit key */
		private string $basePath;

		/** @var int Maximum time to wait for a key's lock (seconds) */
		private int $lockTimeout;

		/** @var int Seconds after which an untouched state file is swept as garbage */
		private int $staleAfterSeconds;

		/**
		 * Constructor
		 * @param array<string, mixed> $config
		 *   - path: storage directory (default: storage/rate_limit under the project root)
		 *   - lock_timeout: max seconds to wait for a key's lock (default 5)
		 *   - stale_after: seconds before an untouched state file is swept as garbage
		 *     (default 86400); must be larger than the longest configured window,
		 *     otherwise an in-progress fixed window could be swept mid-window
		 */
		public function __construct(array $config = []) {
			$lockTimeout = $config['lock_timeout'] ?? 5;
			$this->lockTimeout = is_int($lockTimeout) && $lockTimeout > 0 ? $lockTimeout : 5;

			$staleAfter = $config['stale_after'] ?? self::DEFAULT_STALE_AFTER_SECONDS;
			$this->staleAfterSeconds = is_int($staleAfter) && $staleAfter > 0 ? $staleAfter : self::DEFAULT_STALE_AFTER_SECONDS;

			$path = $config['path'] ?? null;
			
			if (is_string($path) && $path !== '') {
				$this->basePath = rtrim($path, '/\\');
			} else {
				$this->basePath = rtrim(ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'rate_limit', '/\\');
			}

			$this->ensureDirectoryExists();
		}

		/**
		 * @inheritDoc
		 */
		public function incrementFixedWindow(string $key, int $limit, int $window, int $now): RateLimitResult {
			$this->assertWindowFitsRetention($window);
			
			$stateKey = $key . ':fixed:' . intdiv($now, $window) * $window;

			$result = $this->withLock($stateKey, function ($handle) use ($limit, $window, $now) {
				$admission = RateLimitMath::fixedWindow($this->readState($handle), $limit, $window, $now);
				$this->writeState($handle, $admission->getState());
				return $admission->getResult();
			});

			$this->maybeGarbageCollect();
			return $result;
		}

		/**
		 * @inheritDoc
		 */
		public function admitSlidingWindow(string $key, int $limit, int $window, int $now): RateLimitResult {
			$this->assertWindowFitsRetention($window);

			$result = $this->withLock($key . ':sliding', function ($handle) use ($limit, $window, $now) {
				$admission = RateLimitMath::slidingWindow($this->readState($handle), $limit, $window, $now);
				$this->writeState($handle, $admission->getState());
				return $admission->getResult();
			});

			$this->maybeGarbageCollect();
			return $result;
		}

		/**
		 * @inheritDoc
		 */
		public function admitTokenBucket(string $key, int $limit, int $window, int $now): RateLimitResult {
			$this->assertWindowFitsRetention($window);

			$result = $this->withLock($key . ':bucket', function ($handle) use ($limit, $window, $now) {
				$admission = RateLimitMath::tokenBucket($this->readState($handle), $limit, $window, $now);
				$this->writeState($handle, $admission->getState());
				return $admission->getResult();
			});

			$this->maybeGarbageCollect();
			return $result;
		}

		/**
		 * Guards the constructor's documented invariant that stale_after must exceed
		 * the longest configured window, otherwise garbage collection could sweep an
		 * in-progress window's state as if it were abandoned.
		 * @param int $window Window length in seconds for the current admission call
		 * @return void
		 * @throws RateLimitStoreUnavailableException
		 */
		private function assertWindowFitsRetention(int $window): void {
			if ($window >= $this->staleAfterSeconds) {
				throw new RateLimitStoreUnavailableException(
					"Rate limit window ({$window}s) must be smaller than the store's stale_after ({$this->staleAfterSeconds}s), " .
					"otherwise garbage collection can sweep an in-progress window"
				);
			}
		}

		/** @var int Bound on retries when the opened file turns out to be orphaned by a concurrent GC unlink */
		private const int MAX_ORPHANED_HANDLE_RETRIES = 10;

		/**
		 * Open the state file for $stateKey, hold an exclusive lock across the whole
		 * operation, and run $operation against that single locked handle. Retries on a
		 * fresh handle if maybeGarbageCollect() unlinked $path between fopen() and flock(),
		 * which would otherwise leave this handle locking an inode $path no longer resolves to - see sameFile().
		 * @template T
		 * @param string $stateKey
		 * @param callable(resource): T $operation
		 * @return T
		 * @throws RateLimitStoreUnavailableException
		 */
		private function withLock(string $stateKey, callable $operation): mixed {
			$path = $this->statePath($stateKey);

			for ($attempt = 0; $attempt < self::MAX_ORPHANED_HANDLE_RETRIES; $attempt++) {
				$handle = @fopen($path, 'c+');

				if ($handle === false) {
					throw new RateLimitStoreUnavailableException("Could not open rate limit state file for key: {$stateKey}");
				}

				try {
					if (!$this->acquireExclusiveLock($handle)) {
						throw new RateLimitStoreUnavailableException("Could not acquire rate limit lock for key: {$stateKey}");
					}

					if (!$this->sameFile($handle, $path)) {
						continue;
					}

					return $operation($handle);
				} finally {
					flock($handle, LOCK_UN);
					fclose($handle);
				}
			}

			throw new RateLimitStoreUnavailableException("Could not obtain a stable rate limit lock for key: {$stateKey}");
		}

		/**
		 * Detects whether $path still refers to the inode $handle has locked - see withLock(). A stat failure counts as "not the same file" so the caller retries.
		 * @param resource $handle
		 * @param string $path
		 * @return bool
		 */
		private function sameFile($handle, string $path): bool {
			$handleStats = fstat($handle);
			$pathStats = @stat($path);

			if (!is_array($handleStats) || !is_array($pathStats)) {
				return false;
			}

			return $handleStats['dev'] === $pathStats['dev'] && $handleStats['ino'] === $pathStats['ino'];
		}

		/**
		 * Non-blocking lock acquisition with a timeout, to avoid blocking indefinitely
		 * if a prior lock holder died while holding it.
		 * @param resource $handle
		 * @return bool True if the exclusive lock was acquired within the timeout
		 */
		private function acquireExclusiveLock($handle): bool {
			$start = microtime(true);

			while (microtime(true) - $start < $this->lockTimeout) {
				if (flock($handle, LOCK_EX | LOCK_NB)) {
					return true;
				}

				usleep(5000);
			}

			return false;
		}

		/**
		 * Read the current state from an already-locked handle. A size of zero is treated as
		 * "fresh" (see the class docblock's known limitation for the one case that's wrong);
		 * any state that exists but cannot be read back as the shape this class itself wrote
		 * is reported as unavailable rather than silently reset.
		 * @param resource $handle
		 * @return array<string, mixed>|null
		 * @throws RateLimitStoreUnavailableException
		 */
		private function readState($handle): ?array {
			fseek($handle, 0);
			$stats = fstat($handle);
			$size = is_array($stats) && is_int($stats['size'] ?? null) ? $stats['size'] : 0;

			if ($size <= 0) {
				return null;
			}

			$contents = fread($handle, $size);

			if ($contents === false || $contents === '') {
				throw new RateLimitStoreUnavailableException('Could not read rate limit state file');
			}

			$data = @unserialize($contents);
			$state = is_array($data) ? $this->asStringKeyedArray($data) : null;

			if ($state === null) {
				throw new RateLimitStoreUnavailableException('Rate limit state file contains corrupt or unexpected data');
			}

			return $state;
		}

		/**
		 * Validates that $data is an array keyed entirely by strings, as the state
		 * this class itself serializes always is. Deserialized data is untrusted -
		 * a corrupted or foreign-format state file is treated as no state at all
		 * rather than passed through with an unverified key type.
		 * @param mixed $data
		 * @return array<string, mixed>|null
		 */
		private function asStringKeyedArray(mixed $data): ?array {
			if (!is_array($data)) {
				return null;
			}

			$result = [];

			foreach ($data as $key => $value) {
				if (!is_string($key)) {
					return null;
				}

				$result[$key] = $value;
			}

			return $result;
		}

		/**
		 * Overwrite the state on an already-locked handle in place. Every step is checked, and
		 * writing before truncating means a failed write leaves old content intact or corrupt,
		 * never empty - except on a key's first-ever write, which has no old content to fall
		 * back to; see the class docblock's known limitation.
		 * @param resource $handle
		 * @param array<string, mixed> $state
		 * @return void
		 * @throws RateLimitStoreUnavailableException
		 */
		private function writeState($handle, array $state): void {
			$serialized = serialize($state);

			if (
				fseek($handle, 0) !== 0 ||
				fwrite($handle, $serialized) !== strlen($serialized) ||
				ftruncate($handle, strlen($serialized)) === false ||
				fflush($handle) === false
			) {
				throw new RateLimitStoreUnavailableException('Could not persist rate limit state');
			}
		}

		/**
		 * Full path to a key's state file
		 * @param string $stateKey
		 * @return string
		 */
		private function statePath(string $stateKey): string {
			return $this->basePath . DIRECTORY_SEPARATOR . hash('sha256', $stateKey) . '.state';
		}
		
		/**
		 * Probabilistic passive cleanup of state files whose key has gone inactive
		 * (e.g. a fixed window that will never be read again). Runs on roughly 1 in
		 * GC_PROBABILITY admission calls instead of requiring an external cron job.
		 * @return void
		 * @throws RandomException
		 */
		private function maybeGarbageCollect(): void {
			if (random_int(1, self::GC_PROBABILITY) !== 1) {
				return;
			}

			$staleBefore = time() - $this->staleAfterSeconds;
			$files = @glob($this->basePath . DIRECTORY_SEPARATOR . '*.state') ?: [];

			foreach ($files as $file) {
				$mtime = @filemtime($file);

				if ($mtime !== false && $mtime < $staleBefore) {
					$this->deleteIfUnlocked($file, $staleBefore);
				}
			}
		}

		/**
		 * Deletes $file only while holding its exclusive lock, so a key that
		 * withLock() still has open for an in-progress admission - which holds that
		 * same lock for its entire operation - is never removed out from under it.
		 * Age is rechecked here under the lock since a request can refresh the key
		 * between the caller's unlocked check and the lock being acquired here.
		 * @param string $file
		 * @param int $staleBefore Modification times before this are considered stale
		 * @return void
		 */
		private function deleteIfUnlocked(string $file, int $staleBefore): void {
			$handle = @fopen($file, 'r+');

			if ($handle === false) {
				return;
			}

			try {
				if (flock($handle, LOCK_EX | LOCK_NB)) {
					clearstatcache(true, $file);
					$mtime = @filemtime($file);

					if ($mtime !== false && $mtime < $staleBefore) {
						@unlink($file);
					}
				}
			} finally {
				flock($handle, LOCK_UN);
				fclose($handle);
			}
		}

		/**
		 * Ensure the storage directory exists
		 * @return void
		 * @throws RateLimitStoreUnavailableException
		 */
		private function ensureDirectoryExists(): void {
			if (!is_dir($this->basePath)) {
				@mkdir($this->basePath, 0755, true);

				if (!is_dir($this->basePath)) {
					throw new RateLimitStoreUnavailableException("Could not create rate limit storage directory: {$this->basePath}");
				}
			}
		}
	}
