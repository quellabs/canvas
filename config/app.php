<?php

	return [
		// True to put the framework in debug mode; this mainly affects caching
		'debug_mode'              => true,

		// Directory the web server document root is set to
		'public_directory'        => 'public',

		// Template engine
		'template_engine'         => 'smarty',

		// Optional OutputFilterInterface class, or an ordered list of classes applied
		// in turn; use \Quellabs\Canvas\Output\HtmlMinifyFilter::class to minify HTML.
		'output_filter'           => null,

		// Path to controller classes
		'controller_directory'    => dirname(__FILE__) . '/../src/Controllers',

		// Path to error handlers
		'error_handler_directory' => dirname(__FILE__) . '/../src/Errors',

		// Path to aspect-oriented programming files
		'aspect_directory'        => dirname(__FILE__) . '/../src/Aspects',

		// Path to tasks (Scheduler)
		'scheduler_directory'     => dirname(__FILE__) . '/../src/Tasks',

		// Path to signal listeners
		'signal_listeners_path'   => dirname(__FILE__) . '/../src/Listeners',

		// Default file for Monolog logging
		'monolog_file'            => dirname(__FILE__) . '/../storage/logs/canvas.log',

		// Whether to match routes with trailing slashes
		'match_trailing_slashes'  => false,

		// Metadata source for annotations, read at runtime and written by make:* generators:
		// Configuration::SOURCE_DOCBLOCKS (@Route(...)) or SOURCE_ATTRIBUTES (#[Route(...)])
		'annotation_source'       => \Quellabs\AnnotationReader\Configuration::SOURCE_DOCBLOCKS,

		// Default SecurityHeaderPolicyInterface implementation used by SecurityHeadersAspect
		// (unless overridden per route) and DefaultErrorHandler. Set null to disable.
		// Built-in policies: Basic, Medium, and Strict (Quellabs\Canvas\Security\Policies).
		'security_header_policy'  => \Quellabs\Canvas\Security\Policies\BasicSecurityHeaderPolicy::class
	];
