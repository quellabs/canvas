<?php
	
	namespace Quellabs\Canvas\Controllers;
	
	use Quellabs\DependencyInjection\Container;
	use Quellabs\ObjectQuel\ObjectQuel\QuelException;
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
		
		/** @var PropertyHandler Handler for entity property manipulation via reflection */
		protected PropertyHandler $propertyHandler;
		
		/** @var JsonApiSerializer Serializer for converting entities to JSON:API format */
		protected JsonApiSerializer $serializer;
		
		/**
		 * Constructor - initializes the controller with required dependencies
		 * @param Container $container Dependency injector
		 * @param PropertyHandler $propertyHandler Handler for dynamic property access
		 */
		public function __construct(
			Container       $container,
			PropertyHandler $propertyHandler
		) {
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
		 * Get the base URL for API endpoints
		 * Can be overriden
		 * @return string The base URL (e.g., "https://api.example.com")
		 */
		protected function getBaseUrl(): string {
			$scheme = $_SERVER['REQUEST_SCHEME'];
			$host = $_SERVER['HTTP_HOST'];
			return "{$scheme}://{$host}/api";
		}

		/**
		 * Generic GET method for retrieving a single resource by ID
		 * @param int $id The unique identifier of the resource to retrieve
		 * @return JsonResponse JSON:API formatted response containing the resource or error
		 * @throws QuelException
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
		 */
		protected function createResource(Request $request): JsonResponse {
			// Fetch entity manager
			$em = $this->em();
			
			// Parse the JSON request body
			$data = json_decode($request->getContent(), true);
			
			// Validate that the request follows JSON:API structure requirements
			$validationResponse = $this->validateJsonApiStructure($data);
			
			if ($validationResponse) {
				return $validationResponse;
			}
			
			// Create a new instance of the entity class
			$entityClass = $this->getEntityClass();
			$entity = new $entityClass();
			
			// Extract attributes from the JSON:API request structure
			$attributes = $data["data"]["attributes"] ?? [];
			
			// Validate attributes before creating/updating
			$validationResponse = $this->validateAttributes($entity, $attributes);
			
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
		 * @throws OrmException|QuelException
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
			$data = json_decode($request->getContent(), true);
			
			// Validate that the request follows JSON:API structure requirements
			$validationResponse = $this->validateJsonApiStructure($data);
			
			if ($validationResponse) {
				return $validationResponse;
			}
			
			// Ensure the ID in the request body matches the URL parameter (if provided)
			if (isset($data["data"]["id"]) && (string)$data["data"]["id"] !== (string)$id) {
				return $this->createIdMismatchResponse();
			}
			
			// Extract attributes from the JSON:API request structure
			$attributes = $data["data"]["attributes"] ?? [];

			// Validate attributes before creating/updating
			$validationResponse = $this->validateAttributes($entity, $attributes);
			
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
		 * Validate that the request data follows JSON:API specification structure
		 * @param array $data The parsed JSON request data
		 * @return JsonResponse|null Error response if validation fails, null if valid
		 */
		protected function validateJsonApiStructure(array $data): ?JsonResponse {
			// Check for required JSON:API structure: data.type must be present
			if (!isset($data["data"]) || !isset($data["data"]["type"])) {
				return $this->json([
					"errors" => [[
						"status" => "400",
						"title"  => "Invalid request format",
						"detail" => "Request must follow JSON:API format with data.type"
					]]
				], 400);
			}
			
			// Verify the resource type matches what this controller handles
			if ($data["data"]["type"] !== $this->getResourceType()) {
				return $this->json([
					"errors" => [[
						"status" => "409",
						"title"  => "Resource type mismatch",
						"detail" => "Expected type '{$this->getResourceType()}' but received '{$data["data"]["type"]}'"
					]]
				], 409);
			}
			
			// Return null if validation passes
			return null;
		}
		
		/**
		 * Validate that all provided attributes can be mapped to entity properties
		 * @param object $entity The entity instance to validate against
		 * @param array $attributes Associative array of attribute name => value pairs
		 * @return JsonResponse|null Error response if validation fails, null if valid
		 */
		protected function validateAttributes(object $entity, array $attributes): ?JsonResponse {
			$unknownAttributes = [];
			
			foreach ($attributes as $key => $value) {
				$setterMethod = 'set' . ucfirst($key);
				
				if (
					!method_exists($entity, $setterMethod) &&
					!$this->propertyHandler->exists($entity, $key)) {
					$unknownAttributes[] = $key;
				}
			}
			
			if (!empty($unknownAttributes)) {
				return $this->json([
					"errors" => [[
						"status" => "422",
						"title"  => "Invalid attributes",
						"detail" => "Unknown attributes: " . implode(', ', $unknownAttributes),
						"source" => ["pointer" => "/data/attributes"]
					]]
				], 422);
			}
			
			return null;
		}
		
		/**
		 * Map JSON:API attributes to entity properties
		 * @param object $entity The entity instance to update
		 * @param array $attributes Associative array of attribute name => value pairs
		 */
		protected function mapAttributesToEntity(object $entity, array $attributes): void {
			foreach ($attributes as $key => $value) {
				// Try using a setter method first (follows naming convention: setPropertyName)
				$setterMethod = 'set' . ucfirst($key);
				
				if (method_exists($entity, $setterMethod)) {
					// Use the setter method if it exists (preferred approach)
					$entity->$setterMethod($value);
				} elseif ($this->propertyHandler->exists($entity, $key)) {
					// Fall back to direct property access if setter doesn't exist
					$this->propertyHandler->set($entity, $key, $value);
				}
			}
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
		 * @return string The fully qualified class name of the entity
		 */
		abstract protected function getEntityClass(): string;
		
		/**
		 * Get the JSON:API resource type identifier for this controller
		 * @return string The JSON:API resource type identifier
		 */
		abstract protected function getResourceType(): string;
		
	}