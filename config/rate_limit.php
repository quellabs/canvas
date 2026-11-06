<?php

	// Backend used by Quellabs\Canvas\Security\RateLimit\RateLimitStoreFactory to build the
	// RateLimitStoreInterface that RateLimitAspect resolves through dependency injection.
	// Each backend performs the read-decide-write admission cycle as a single atomic
	// operation, so concurrent requests can never read the same count and both be admitted.

	return [
		// Which driver below to use
		'driver'  => 'file',

		'drivers' => [
			// File-backed store: one state file per key, with a single exclusive lock
			// held across the whole read-decide-write cycle. No extra service required;
			// suitable for a single server. Not safe to share across multiple servers
			// unless they share the same filesystem (e.g. NFS) - use redis or memcached
			// for a multi-server deployment.
			'file'      => [
				'class' => \Quellabs\Canvas\Security\RateLimit\FileRateLimitStore::class,

				// Max seconds to wait for a key's lock before failing
				'lock_timeout' => 5,

				// Seconds before an untouched state file is swept as garbage.
				// Must be larger than the longest configured window.
				'stale_after'  => 86400,
			],

			// Redis-backed store: each admission runs as one Lua script (EVAL), atomic
			// on Redis's single-threaded command execution. Recommended for multi-server
			// deployments.
			'redis'     => [
				'class'        => \Quellabs\Canvas\Security\RateLimit\RedisRateLimitStore::class,
				'host'         => '127.0.0.1',
				'port'         => 6379,
				'timeout'      => 2.5,
				'read_timeout' => 2.5,
				'database'     => 0,
				'password'     => null,
			],

			// Memcached-backed store: each admission uses compare-and-swap (CAS) with
			// bounded retries, since Memcached has no server-side scripting.
			'memcached' => [
				'class'   => \Quellabs\Canvas\Security\RateLimit\MemcachedRateLimitStore::class,
				'servers' => [
					['127.0.0.1', 11211, 100],
				],

				// Max CAS retries before a key's admission fails as unavailable
				'max_cas_retries' => 10,
			],
		],
	];
