<?php
	
	namespace Quellabs\Canvas\Controllers;
	
	use Quellabs\DependencyInjection\Container;
	use Quellabs\ObjectQuel\Exception\EntityResolutionException;
	use Quellabs\ObjectQuel\Exception\QuelException;
	use Quellabs\ObjectQuel\OrmException;
	use Quellabs\ObjectQuel\ReflectionManagement\PropertyHandler;
	use Quellabs\ObjectQuel\Serialization\Serializers\JsonApiSerializer;
	use Quellabs\ObjectQuel\Serialization\UrlBuilders\JsonApiUrlBuilder;
	use Symfony\Component\HttpFoundation\JsonResponse;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Abstract base controller for JSON:API compliant endpoints
	 *
	 * This controller provides common CRUD operations that follow the JSON:API specification
	 * (https://jsonapi.org/). It handles standard HTTP methods (GET, POST, PUT/PATCH, DELETE)
	 * and ensures proper JSON:API response formatting with error handling.
	 *
	 * Concrete controllers should extend this class and implement the required abstract methods
	 * to define their specific entity and resource type.
	 */
	abstract class JsonApiController extends BaseController {
		
		/** @var JsonApiSerializer Serializer for converting entities to JSON:API format */
		protected JsonApiSerializer $serializer;

		/** @var PropertyHandler Handler for writing entity properties that have no setter */
		protected PropertyHandler $propertyHandler;

		/**
		 * Constructor - initializes the controller with required dependencies
		 * @param Container $container Dependency injector
		 * @param PropertyHandler $propertyHandler Handler for dynamic property access
		 */
		public function __construct(Container $container, PropertyHandler $propertyHandler) {
			parent::__construct($container);
			$this->propertyHandler = $propertyHandler;
			$this->serializer = $this->createSerializer();
		}
		
		/**
		 * Create the JSON API serializer with URL builder
		 * Override this method in concrete controllers to customize base URL or URL builder
		 * @return JsonApiSerializer
		 */
		protected function createSerializer(): JsonApiSerializer {
			$urlBuilder = new JsonApiUrlBuilder($this->getBaseUrl());
			return new JsonApiSerializer($this->em(), $urlBuilder);
		}
		
		/**
		 * Get the base URL for API endpoints. Can be overriden
		 * @return string The base URL (e.g., "https://api.example.com")
		 */
		protected function getBaseUrl(): string {
			// Use ?? null to avoid E_WARNING when the key is absent; $_SERVER values are mixed
			$rawScheme = $_SERVER['REQUEST_SCHEME'] ?? null;
			$rawHost = $_SERVER['HTTP_HOST'] ?? null;
			
			// is_string() narrows mixed to string for PHPStan; fall back if key is absent or non-string
			$scheme = is_string($rawScheme) ? $rawScheme : 'https';
			$host = is_string($rawHost) ? $rawHost : 'localhost';
			return "{$scheme}://{$host}/api";
		}
		
		/**
		 * Generic GET method for retrieving a single resource by ID
		 * @param int $id The unique identifier of the resource to retrieve
		 * @return JsonResponse JSON:API formatted response containing the resource or error
		 * @throws QuelException|EntityResolutionException
		 */
		protected function getResource(int $id): JsonResponse {
			// Fetch entity manager
			$em = $this->em();
			
			// Attempt to find the entity by ID using the entity manager
			$entity = $em->find($this->getEntityClass(), $id);
			
			// Return 404 if entity doesn't exist
			if (!$entity) {
				return $this->createNotFoundResponse($this->getResourceType());
			}
			
			// Serialize the entity to JSON:API format and return
			return $this->json($this->serializer->serialize($entity));
		}
		
		/**
		 * Generic POST method for creating a new resource
		 * @param Request $request The HTTP request containing JSON:API formatted data
		 * @return JsonResponse JSON:API formatted response with created resource or errors
		 * @throws OrmException
		 * @throws QuelException
		 * @throws EntityResolutionException
		 */
		protected function createResource(Request $request): JsonResponse {
			// Fetch entity manager
			$em = $this->em();
			
			// Parse the JSON request body
			$decoded = json_decode($request->getContent(), true);
			
			// Validate that json_decode produced a usable array
			if (!is_array($decoded)) {
				return $this->json([
					"errors" => [[
						"status" => "400",
						"title"  => "Invalid request body",
						"detail" => "Request body must be valid JSON"
					]]
				], 400);
			}
			
			/** @var array<string, mixed> $data */
			$data = $decoded;
			
			// Validate that the request follows JSON:API structure requirements
			$validationResponse = $this->validateJsonApiStructure($data);
			
			if ($validationResponse) {
				return $validationResponse;
			}
			
			// Create a new instance of the entity class
			$entityClass = $this->getEntityClass();
			$entity = new $entityClass();

			// Resource- or user-specific authorization beyond the per-attribute check
			$authorizationResponse = $this->authorizeAttributeWrite($request, $entity, WriteOperation::Create);

			if ($authorizationResponse) {
				return $authorizationResponse;
			}

			// Extract attributes from the JSON:API request structure
			$attributes = $this->extractAttributes($data);

			// Validate attributes before creating/updating
			$validationResponse = $this->validateAttributes($entity, $attributes, WriteOperation::Create);

			if ($validationResponse) {
				return $validationResponse;
			}

			// Map the provided attributes to the entity properties
			$this->mapAttributesToEntity($entity, $attributes);

			// Persist the new entity to the database
			$em->persist($entity);
			$em->flush();
			
			// Return the created resource with 201 status code
			$serializedData = $this->serializer->serialize($entity);
			return $this->json($serializedData, 201);
		}
		
		/**
		 * Generic PUT/PATCH method for updating an existing resource
		 * @param int $id The unique identifier of the resource to update
		 * @param Request $request The HTTP request containing JSON:API formatted update data
		 * @return JsonResponse JSON:API formatted response with updated resource or errors
		 * @throws OrmException|QuelException|EntityResolutionException
		 */
		protected function updateResource(int $id, Request $request): JsonResponse {
			// Fetch entity manager
			$em = $this->em();
			
			// Find the existing entity by ID
			$entity = $em->find($this->getEntityClass(), $id);
			
			// Return 404 if entity doesn't exist
			if (!$entity) {
				return $this->createNotFoundResponse($this->getResourceType());
			}
			
			// Parse the JSON request body
			$decoded = json_decode($request->getContent(), true);
			
			// Validate that json_decode produced a usable array
			if (!is_array($decoded)) {
				return $this->json([
					"errors" => [[
						"status" => "400",
						"title"  => "Invalid request body",
						"detail" => "Request body must be valid JSON"
					]]
				], 400);
			}
			
			/** @var array<string, mixed> $data */
			$data = $decoded;
			
			// Validate that the request follows JSON:API structure requirements
			$validationResponse = $this->validateJsonApiStructure($data);
			
			if ($validationResponse) {
				return $validationResponse;
			}
			
			// Ensure the ID in the request body matches the URL parameter (if provided)
			$requestId = $this->extractId($data);
			
			if ($requestId !== null && $requestId !== (string)$id) {
				return $this->createIdMismatchResponse();
			}

			// Resource- or user-specific authorization beyond the per-attribute check
			$authorizationResponse = $this->authorizeAttributeWrite($request, $entity, WriteOperation::Update);

			if ($authorizationResponse) {
				return $authorizationResponse;
			}

			// Extract attributes from the JSON:API request structure
			$attributes = $this->extractAttributes($data);

			// Validate attributes before creating/updating
			$validationResponse = $this->validateAttributes($entity, $attributes, WriteOperation::Update);

			if ($validationResponse) {
				return $validationResponse;
			}
			
			// Map the provided attributes to the entity properties
			$this->mapAttributesToEntity($entity, $attributes);
			
			// Save the changes to the database
			$em->flush();
			
			// Return the updated resource
			$serializedData = $this->serializer->serialize($entity);
			return $this->json($serializedData);
		}
		
		/**
		 * Generic DELETE method for removing a resource
		 * @param int $id The unique identifier of the resource to delete
		 * @return JsonResponse Empty response with 204 status code or 404 error
		 * @throws OrmException|QuelException
		 */
		protected function deleteResource(int $id): JsonResponse {
			// Fetch entity manager
			$em = $this->em();
			
			// Find the entity to delete
			$entity = $em->find($this->getEntityClass(), $id);
			
			// Return 404 if entity doesn't exist
			if (!$entity) {
				return $this->createNotFoundResponse($this->getResourceType());
			}
			
			// Remove the entity from the database
			$em->remove($entity);
			$em->flush();
			
			// Return 204 No Content as per JSON:API specification for successful deletion
			return new JsonResponse(null, 204);
		}
		
		/**
		 * Extract attributes from a validated JSON:API data block
		 * @param array<string, mixed> $data The parsed and validated JSON:API request data
		 * @return array<string, mixed>
		 */
		private function extractAttributes(array $data): array {
			$dataBlock = $data["data"];
			
			if (!is_array($dataBlock)) {
				return [];
			}
			
			$attributes = $dataBlock["attributes"] ?? [];
			return is_array($attributes) ? $attributes : [];
		}
		
		/**
		 * Extract the resource ID from a validated JSON:API data block, or null if absent
		 * @param array<string, mixed> $data The parsed and validated JSON:API request data
		 * @return string|null
		 */
		private function extractId(array $data): ?string {
			$dataBlock = $data["data"];
			
			if (!is_array($dataBlock) || !isset($dataBlock["id"])) {
				return null;
			}
			
			$id = $dataBlock["id"];
			
			if (is_string($id)) {
				return $id;
			}
			
			if (is_int($id) || is_float($id)) {
				return (string)$id;
			}
			
			return null;
		}
		
		/**
		 * Validate that the request data follows JSON:API specification structure
		 * @param array<string, mixed> $data The parsed JSON request data
		 * @return JsonResponse|null Error response if validation fails, null if valid
		 */
		protected function validateJsonApiStructure(array $data): ?JsonResponse {
			// Check for required JSON:API structure: data.type must be present
			$dataBlock = $data["data"] ?? null;
			
			if (!is_array($dataBlock) || !isset($dataBlock["type"]) || !is_string($dataBlock["type"])) {
				return $this->json([
					"errors" => [[
						"status" => "400",
						"title"  => "Invalid request format",
						"detail" => "Request must follow JSON:API format with data.type"
					]]
				], 400);
			}
			
			$receivedType = $dataBlock["type"];
			
			// Verify the resource type matches what this controller handles
			if ($receivedType !== $this->getResourceType()) {
				return $this->json([
					"errors" => [[
						"status" => "409",
						"title"  => "Resource type mismatch",
						"detail" => "Expected type '{$this->getResourceType()}' but received '{$receivedType}'"
					]]
				], 409);
			}
			
			// Return null if validation passes
			return null;
		}
		
		/**
		 * Validate every submitted attribute before anything is mapped onto the
		 * entity. The primary key is always forbidden, regardless of what a
		 * concrete controller does — a client can never reassign which row a
		 * request writes to. An attribute that isn't a property on the entity at
		 * all is silently ignored (typo, stale client field; mapAttributesToEntity()
		 * is a no-op for it either way). Everything else — whether or not it has
		 * a setter — is decided solely by isAttributeWritable(); that's the one
		 * and only write gate.
		 * @param object $entity The entity instance to validate against
		 * @param array<string, mixed> $attributes Associative array of attribute name => value pairs
		 * @param WriteOperation $operation Whether this is a create or an update
		 * @return JsonResponse|null Error response if validation fails, null if valid
		 * @throws EntityResolutionException
		 */
		protected function validateAttributes(object $entity, array $attributes, WriteOperation $operation): ?JsonResponse {
			$metadata = $this->em()->getEntityStore()->getMetadata($entity);
			$forbiddenAttributes = [];

			foreach ($attributes as $key => $value) {
				if ($metadata->isIdentifierKey($key)) {
					$forbiddenAttributes[] = $key;
					continue;
				}

				if (!$this->attributeExistsOnEntity($entity, $key)) {
					continue;
				}

				if (!$this->isAttributeWritable($entity, $key, $operation)) {
					$forbiddenAttributes[] = $key;
				}
			}

			if (!empty($forbiddenAttributes)) {
				return $this->createForbiddenAttributesResponse($forbiddenAttributes);
			}

			return null;
		}

		/**
		 * Map JSON:API attributes to entity properties: through the setter when
		 * one exists (naming convention: setPropertyName), otherwise directly via
		 * reflection. A key that isn't a property on the entity at all is a no-op.
		 * @param object $entity The entity instance to update
		 * @param array<string, mixed> $attributes Associative array of attribute name => value pairs
		 */
		protected function mapAttributesToEntity(object $entity, array $attributes): void {
			foreach ($attributes as $key => $value) {
				$setterMethod = 'set' . ucfirst($key);

				if (method_exists($entity, $setterMethod)) {
					$entity->$setterMethod($value);
				} elseif ($this->propertyHandler->exists($entity, $key)) {
					$this->propertyHandler->set($entity, $key, $value);
				}
			}
		}

		/**
		 * Check whether an attribute corresponds to a real property on the
		 * entity, through a setter or through reflection. Mirrors the write
		 * mechanism mapAttributesToEntity() actually uses, so nothing can pass
		 * validation here and then silently fail to be written.
		 * @param object $entity
		 * @param string $key
		 * @return bool
		 */
		private function attributeExistsOnEntity(object $entity, string $key): bool {
			return method_exists($entity, 'set' . ucfirst($key)) || $this->propertyHandler->exists($entity, $key);
		}

		/**
		 * Authorize a write before any attribute is validated or mapped. The default
		 * allows every create/update; override to add resource- or user-specific
		 * checks (ownership, role, current entity state) that a per-attribute
		 * decision can't express — for example, rejecting an update to a resource
		 * the current user doesn't own, regardless of which fields were submitted.
		 * @param Request $request The incoming HTTP request
		 * @param object $entity The entity being created or updated
		 * @param WriteOperation $operation Whether this is a create or an update
		 * @return JsonResponse|null Error response (typically 403) to deny the write, or null to allow it
		 */
		protected function authorizeAttributeWrite(Request $request, object $entity, WriteOperation $operation): ?JsonResponse {
			return null;
		}

		/**
		 * Create a standardized 403 response for attributes that exist on the
		 * entity but are denied for this operation — either by isAttributeWritable()
		 * or because the attribute is the primary key, which is never writable
		 * regardless of what a controller does.
		 * @param list<string> $attributeNames
		 * @return JsonResponse
		 */
		protected function createForbiddenAttributesResponse(array $attributeNames): JsonResponse {
			return $this->json([
				"errors" => array_map(fn(string $name) => [
					"status" => "403",
					"title"  => "Forbidden attribute",
					"detail" => "Attribute '{$name}' is not writable for this operation",
					"source" => ["pointer" => "/data/attributes/{$name}"]
				], $attributeNames)
			], 403);
		}

		/**
		 * Create a standardized 404 Not Found response following JSON:API error format
		 * @param string $resourceType The type of resource that was not found
		 * @return JsonResponse JSON:API compliant error response
		 */
		protected function createNotFoundResponse(string $resourceType): JsonResponse {
			return $this->json([
				"errors" => [[
					"status" => "404",
					"title"  => "Resource not found",
					"detail" => "The requested {$resourceType} resource could not be found"
				]]
			], 404);
		}
		
		/**
		 * Create a standardized ID mismatch error response
		 * Used when the ID in the URL doesn't match the ID in the request body
		 * during update operations, which violates JSON:API consistency requirements.
		 * @return JsonResponse JSON:API compliant error response
		 */
		protected function createIdMismatchResponse(): JsonResponse {
			return $this->json([
				"errors" => [[
					"status" => "400",
					"title"  => "ID mismatch",
					"detail" => "ID in URL does not match ID in request body"
				]]
			], 400);
		}
		
		/**
		 * Get the fully qualified entity class name for this controller
		 * This method must be implemented by concrete controllers to specify
		 * which entity class they operate on (e.g., App\Entity\User::class)
		 * @return class-string The fully qualified class name of the entity
		 */
		abstract protected function getEntityClass(): string;

		/**
		 * Get the JSON:API resource type identifier for this controller
		 * @return string The JSON:API resource type identifier
		 */
		abstract protected function getResourceType(): string;

		/**
		 * Decide whether a specific attribute may be written for the given
		 * operation. Only ever called for an attribute that already exists on
		 * the entity (via a setter or directly as a property) — this is the
		 * only write gate; a setter's presence or absence plays no role in the
		 * decision. Defaults to allowing everything; override to deny specific
		 * fields, operations or circumstances — for example: `return $key !== 'role';`
		 * to keep a field server-owned, or `$operation !== WriteOperation::Update`
		 * to allow it only on create.
		 * @param object $entity The entity being created or updated
		 * @param string $key The attribute name (already confirmed to exist on the entity)
		 * @param WriteOperation $operation Whether this is a create or an update
		 * @return bool Whether the client may set this attribute for this operation
		 */
		protected function isAttributeWritable(object $entity, string $key, WriteOperation $operation): bool {
			return true;
		}
	}