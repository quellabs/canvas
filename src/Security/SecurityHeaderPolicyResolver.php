<?php

	namespace Quellabs\Canvas\Security;

	use Quellabs\Canvas\Security\Policies\CompositeSecurityHeaderPolicy;
	use Quellabs\Canvas\Security\Policies\NullSecurityHeaderPolicy;
	use Quellabs\DependencyInjection\Container;

	/**
	 * Shared resolution for config/app.php's security_header_policy and
	 * SecurityHeadersAspect's policyClass: both accept a single class-string or an
	 * ordered, numerically indexed list of class-strings, resolved and validated the
	 * same way in either case. A single class resolves to its own concrete instance;
	 * a list resolves to a CompositeSecurityHeaderPolicy applying each in order.
	 * Callers pick the exception type their own invalid-input contract already uses.
	 */
	class SecurityHeaderPolicyResolver {

		/**
		 * Resolves a single class-string or list<class-string> into a policy instance
		 * @param Container $container Used to construct each resolved policy class
		 * @param string|array<int|string, mixed>|null $policyClass Single class, ordered list of classes, or null (always invalid here; callers that treat null as "use the default" must not call this method with it)
		 * @param string $settingLabel Human-readable name of the setting, used in error messages
		 * @param class-string<\Throwable> $exceptionClass Exception type to throw for invalid input
		 * @return SecurityHeaderPolicyInterface
		 */
		public static function resolve(
			Container $container,
			string|array|null $policyClass,
			string $settingLabel,
			string $exceptionClass
		): SecurityHeaderPolicyInterface {
			if ($policyClass === null) {
				throw new $exceptionClass(sprintf(
					"%s must not be null; use %s::class to disable security headers.",
					$settingLabel,
					NullSecurityHeaderPolicy::class
				));
			}

			if (is_array($policyClass)) {
				return self::resolveList($container, $policyClass, $settingLabel, $exceptionClass);
			}

			return self::resolveSingle($container, $policyClass, $settingLabel, $exceptionClass);
		}

		/**
		 * Resolves a single class-string to its own concrete policy instance
		 * @param Container $container
		 * @param string $class
		 * @param string $settingLabel
		 * @param class-string<\Throwable> $exceptionClass
		 * @return SecurityHeaderPolicyInterface
		 */
		private static function resolveSingle(
			Container $container,
			string $class,
			string $settingLabel,
			string $exceptionClass
		): SecurityHeaderPolicyInterface {
			if (!class_exists($class)) {
				throw new $exceptionClass(sprintf("%s class '%s' does not exist.", $settingLabel, $class));
			}

			$policy = $container->make($class);

			if (!$policy instanceof SecurityHeaderPolicyInterface) {
				throw new $exceptionClass(sprintf(
					"%s class '%s' must implement %s.",
					$settingLabel,
					$class,
					SecurityHeaderPolicyInterface::class
				));
			}

			return $policy;
		}

		/**
		 * Resolves an ordered, numerically indexed list of class-strings into a CompositeSecurityHeaderPolicy
		 * @param array<int|string, mixed> $list
		 * @param Container $container
		 * @param string $settingLabel
		 * @param class-string<\Throwable> $exceptionClass
		 * @return SecurityHeaderPolicyInterface
		 */
		private static function resolveList(
			Container $container,
			array $list,
			string $settingLabel,
			string $exceptionClass
		): SecurityHeaderPolicyInterface {
			if ($list === []) {
				throw new $exceptionClass(sprintf("%s must be a nonempty list.", $settingLabel));
			}

			if (!array_is_list($list)) {
				throw new $exceptionClass(sprintf(
					"%s[%s] is invalid: entries must form a sequential, numerically indexed list.",
					$settingLabel,
					self::firstNonSequentialKey($list)
				));
			}

			$policies = [];

			foreach ($list as $index => $entry) {
				if (!is_string($entry)) {
					throw new $exceptionClass(sprintf(
						"%s[%d] must be a class-string, got %s.",
						$settingLabel,
						$index,
						get_debug_type($entry)
					));
				}

				$policies[] = self::resolveSingle($container, $entry, "{$settingLabel}[{$index}]", $exceptionClass);
			}

			return new CompositeSecurityHeaderPolicy($policies);
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
