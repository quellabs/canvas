<?php

	return [
		'default' => 'file',
		'drivers' => [
			'file'      => [
				'class' => \Quellabs\Canvas\Cache\Drivers\FileCache::class,
			],
			'redis'     => [
				'class'        => \Quellabs\Canvas\Cache\Drivers\RedisCache::class,
				'host'         => '127.0.0.1',
				'port'         => 6379,
				'timeout'      => 2.5,
				'read_timeout' => 2.5,
				'database'     => 0,
				'password'     => null,
			],
			'memcached' => [
				'class'                 => \Quellabs\Canvas\Cache\Drivers\MemcachedCache::class,
				'servers'               => [
					['127.0.0.1', 11211, 100] // [host, port, weight]
				],
				'persistent_id'         => 'cache_pool',
				'compression'           => true,
				'compression_threshold' => 2000, // bytes
			]
		],
	];
