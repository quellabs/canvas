<?php

	namespace Quellabs\Canvas\Output;

	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * Modifies a completed response before the kernel returns it.
	 */
	interface OutputFilterInterface {

		/**
		 * Filters a response in place.
		 * @param Request $request
		 * @param Response $response
		 * @return void
		 */
		public function filter(Request $request, Response $response): void;
	}
