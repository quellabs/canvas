<?php

	namespace Quellabs\Canvas\Output;

	use Quellabs\DependencyInjection\Container;

	/**
	 * Shared resolution for config/app.php's output_filter: accepts a single
	 * class-string, an ordered, numerically indexed list of class-strings, or
	 * null to disable filtering entirely. A single class resolves to its own
	 * concrete instance; a list resolves to a CompositeOutputFilter applying each
	 * in order.
	 */
	class OutputFilterResolver {

		/**
		 * Resolves a single class-string, list<class-string>, or null into a filter instance
		 * @param Container $container Used to construct each resolved filter class
		 * @param string|array<int|string, mixed>|null $filterClass Single class, ordered list of classes, or null to disable filtering
		 * @param string $settingLabel Human-readable name of the setting, used in error messages
		 * @return OutputFilterInterface|null
		 */
		public static function resolve(
			Container $container,
			string|array|null $filterClass,
			string $settingLabel
		): ?OutputFilterInterface {
			if ($filterClass === null) {
				return null;
			}

			if (is_array($filterClass)) {
				return self::resolveList($container, $filterClass, $settingLabel);
			}

			return self::resolveSingle($container, $filterClass, $settingLabel);
		}

		/**
		 * Resolves a single class-string to its own concrete filter instance
		 * @param Container $container
		 * @param string $class
		 * @param string $settingLabel
		 * @return OutputFilterInterface
		 */
		private static function resolveSingle(Container $container, string $class, string $settingLabel): OutputFilterInterface {
			if (!class_exists($class)) {
				throw new \InvalidArgumentException(sprintf("%s class '%s' does not exist.", $settingLabel, $class));
			}

			$filter = $container->make($class);

			if (!$filter instanceof OutputFilterInterface) {
				throw new \InvalidArgumentException(sprintf(
					"%s class '%s' must implement %s.",
					$settingLabel,
					$class,
					OutputFilterInterface::class
				));
			}

			return $filter;
		}

		/**
		 * Resolves an ordered, numerically indexed list of class-strings into a CompositeOutputFilter
		 * @param Container $container
		 * @param array<int|string, mixed> $list
		 * @param string $settingLabel
		 * @return OutputFilterInterface
		 */
		private static function resolveList(Container $container, array $list, string $settingLabel): OutputFilterInterface {
			if ($list === []) {
				throw new \InvalidArgumentException(sprintf("%s must be a nonempty list.", $settingLabel));
			}

			if (!array_is_list($list)) {
				throw new \InvalidArgumentException(sprintf(
					"%s[%s] is invalid: entries must form a sequential, numerically indexed list.",
					$settingLabel,
					self::firstNonSequentialKey($list)
				));
			}

			$filters = [];

			foreach ($list as $index => $entry) {
				if (!is_string($entry)) {
					throw new \InvalidArgumentException(sprintf(
						"%s[%d] must be a class-string, got %s.",
						$settingLabel,
						$index,
						get_debug_type($entry)
					));
				}

				$filters[] = self::resolveSingle($container, $entry, "{$settingLabel}[{$index}]");
			}

			return new CompositeOutputFilter($filters);
		}

		/**
		 * Finds the first key that breaks the expected 0, 1, 2, ... sequence, for use in an error message
		 * @param non-empty-array<int|string, mixed> $list Only called after array_is_list() failed, which is never true for an empty array
		 * @return int|string
		 */
		private static function firstNonSequentialKey(array $list): int|string {
			$expected = 0;

			foreach ($list as $key => $value) {
				if ($key !== $expected) {
					return $key;
				}

				$expected++;
			}

			// Unreachable because array_is_list() already failed, but keeps this helper total
			return array_key_first($list);
		}
	}
