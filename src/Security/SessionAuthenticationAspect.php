<?php

	namespace Quellabs\Canvas\Security;

	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Exceptions\SessionAuthenticationException;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * Session authentication aspect that validates a logged-in session before a method executes.
	 *
	 * This is a validator only — like JwtAuthenticationAspect, it does not perform login
	 * itself. Login code elsewhere in the application is responsible for writing three
	 * session keys on successful credential verification:
	 *
	 *   user_id       — mixed, the authenticated user's identifier (matches the key
	 *                   quellabs/canvas-authorization's scaffolded login flow sets)
	 *   auth_time     — int|float, Unix timestamp of when the credential was proven
	 *   auth_methods  — string[], methods used (RFC 8176 names recommended, e.g. 'pwd')
	 *
	 * and to remove user_id (at minimum) on logout.
	 *
	 * On success, publishes 'session_user_id', 'auth_time', and 'auth_methods' on
	 * $request->attributes — the same 'auth_time'/'auth_methods' contract JwtAuthenticationAspect
	 * publishes, so RecentAuthenticationAspect works unmodified against either authenticator.
	 *
	 * Supports two failure modes, selectable via throwOnFailure:
	 *
	 * - Attribute mode (default): on failure, sets 'session_error' on $request->attributes
	 *   and returns null, allowing the controller to decide how to respond.
	 *
	 * - Exception mode (throwOnFailure=true): throws SessionAuthenticationException,
	 *   which propagates to the kernel's error handler.
	 *
	 * Session lifetime (idle timeout, absolute expiry) is intentionally out of scope —
	 * it's governed by the session storage's own configuration (e.g. session.gc_maxlifetime),
	 * not by this aspect.
	 *
	 * Usage:
	 * @InterceptWith(Quellabs\Canvas\Security\SessionAuthenticationAspect::class)
	 * @InterceptWith(Quellabs\Canvas\Security\SessionAuthenticationAspect::class, throwOnFailure=true)
	 */
	readonly class SessionAuthenticationAspect implements BeforeAspectInterface {

		/**
		 * SessionAuthenticationAspect constructor
		 * @param bool $throwOnFailure If true, throws SessionAuthenticationException instead of writing to request attributes
		 */
		public function __construct(private bool $throwOnFailure = false) {
		}

		/**
		 * Validate the session before the controller method runs.
		 *
		 * On success: sets 'session_user_id', 'auth_time' (when present), and 'auth_methods'
		 * (defaulting to an empty array) on $request->attributes, returns null.
		 *
		 * On failure in attribute mode: sets 'session_error' (reason string) on $request->attributes,
		 * clears 'session_user_id', 'auth_time' and 'auth_methods', returns null.
		 *
		 * On failure in exception mode: throws SessionAuthenticationException.
		 *
		 * @param MethodContextInterface $context
		 * @return Response|null Always null — this aspect never short-circuits via Response.
		 * @throws SessionAuthenticationException When throwOnFailure is true and no authenticated session exists.
		 */
		public function before(MethodContextInterface $context): ?Response {
			$request = $context->getRequest();
			$session = $request->getSession();
			$userId = $session->get('user_id');

			if ($userId === null) {
				if ($this->throwOnFailure) {
					throw new SessionAuthenticationException('No authenticated session');
				}

				// Attribute mode: record the reason and clear any stale auth attributes
				// so downstream aspects and the controller see a consistent unauthenticated state
				$request->attributes->set('session_error', 'No authenticated session');
				$request->attributes->remove('session_user_id');
				$request->attributes->remove('auth_time');
				$request->attributes->remove('auth_methods');
				return null;
			}

			// Session is authenticated — publish the user id and, when present, the
			// auth-mechanism-agnostic freshness attributes consumed by RecentAuthenticationAspect
			$request->attributes->set('session_user_id', $userId);

			$authTime = $session->get('auth_time');

			if (is_int($authTime) || is_float($authTime)) {
				$request->attributes->set('auth_time', $authTime);
			}

			$authMethods = $session->get('auth_methods', []);
			$request->attributes->set('auth_methods', is_array($authMethods) ? $authMethods : []);

			// Clear any session_error left over from a previous attempt on the same request object
			$request->attributes->remove('session_error');
			return null;
		}
	}
