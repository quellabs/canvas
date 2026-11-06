<?php

	// Base source directory relative to config folder
	$srcDir = dirname(__DIR__) . '/src';

	return [
		// True to put the framework in debug mode; this mainly affects caching
		'debug_mode'              => true,

		// Directory the web server document root is set to
		'public_directory'        => 'public',

		// Template engine
		'template_engine'         => 'smarty',

		// Output filter
		'output_filter'           => \Quellabs\Canvas\Output\HtmlMinifyFilter::class,

		// Path to controller classes
		'controller_directory'    => $srcDir . DIRECTORY_SEPARATOR . 'Controllers',

		// Path to error handlers
		'error_handler_directory' => $srcDir . DIRECTORY_SEPARATOR . 'Errors',

		// Path to aspect-oriented programming files
		'aspect_directory'        => $srcDir . DIRECTORY_SEPARATOR . 'Aspects',

		// Path to entity classes
		'entity_path'             => $srcDir . DIRECTORY_SEPARATOR . 'Entities',

		// Path to signal listeners
		'signal_listeners_path'   => $srcDir . DIRECTORY_SEPARATOR . 'Listeners',

		// Whether to match routes with trailing slashes
		'match_trailing_slashes'  => false,

		// Metadata source for annotations, read at runtime and written by make:* generators:
		// Configuration::SOURCE_DOCBLOCKS (@Route(...)) or SOURCE_ATTRIBUTES (#[Route(...)])
		'annotation_source'       => \Quellabs\AnnotationReader\Configuration::SOURCE_ATTRIBUTES,

		// Default SecurityHeaderPolicyInterface implementation used by SecurityHeadersAspect
		// (unless overridden per route) and DefaultErrorHandler. Set null to disable.
		// Built-in policies: Basic, Medium, and Strict (Quellabs\Canvas\Security\Policies).
		'security_header_policy'  => \Quellabs\Canvas\Security\Policies\BasicSecurityHeaderPolicy::class
	];
