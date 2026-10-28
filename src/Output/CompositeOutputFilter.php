<?php

	namespace Quellabs\Canvas\Output;

	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * Applies an ordered list of OutputFilterInterface instances to the same
	 * response. Built by OutputFilterResolver when config/app.php's output_filter
	 * is configured as a list of classes rather than a single one.
	 */
	class CompositeOutputFilter implements OutputFilterInterface {

		/** @var OutputFilterInterface[] Filters applied to the response, in order */
		private array $filters;

		/**
		 * Constructor
		 * @param OutputFilterInterface[] $filters Validated filters, applied in order
		 */
		public function __construct(array $filters) {
			$this->filters = $filters;
		}

		/**
		 * Applies every filter to the response, in order
		 * @param Request $request The request, passed through to each filter
		 * @param Response $response The response to modify
		 * @return void
		 */
		public function filter(Request $request, Response $response): void {
			foreach ($this->filters as $filter) {
				$filter->filter($request, $response);
			}
		}
	}
