<?php

	namespace Quellabs\Canvas\Exceptions;

	/**
	 * Thrown by ValidateAspect when throwOnFailure is enabled and
	 * the submitted data fails validation.
	 *
	 * The framework's exception handler is responsible for converting this
	 * into an appropriate HTTP response. Controllers that want to handle
	 * validation failures themselves (e.g. to re-render a form with errors)
	 * should use the default attribute-based path instead of enabling throwOnFailure,
	 * or catch this exception explicitly in their own exception handler.
	 */
	class ValidationException extends HttpException {

		/** @var array<string, list<string>> Per-field validation errors */
		private array $errors;

		/** @var string|null The ID of the form that failed validation, if any */
		private ?string $formId;

		/**
		 * @param string $message Human-readable summary of the failure
		 * @param array<string, list<string>> $errors Per-field validation errors
		 * @param string|null $formId The ID of the form that failed validation, if any
		 */
		public function __construct(string $message, array $errors, ?string $formId = null) {
			parent::__construct($message, 422);
			$this->errors = $errors;
			$this->formId = $formId;
		}

		/**
		 * Returns the per-field validation error array.
		 * @return array<string, list<string>>
		 */
		public function getErrors(): array {
			return $this->errors;
		}

		/**
		 * Returns the ID of the form that failed validation, or null if none was set.
		 * @return string|null
		 */
		public function getFormId(): ?string {
			return $this->formId;
		}
	}
