<?php

	namespace Quellabs\Canvas\Controllers;

	/**
	 * Distinguishes a JSON:API create (POST) from an update (PUT/PATCH) when
	 * resolving which fields are writable or whether a write is authorized.
	 */
	enum WriteOperation {
		case Create;
		case Update;
	}
