<?php
	
	namespace Quellabs\Canvas\Annotations;
    
    use Quellabs\AnnotationReader\AnnotationInterface;
    
    class BeforeFilter implements AnnotationInterface {
        
        /** @var array<string, mixed> */
        protected array $parameters;
        
        /**
         * Table constructor.
         * @param array<string, mixed> $parameters
         */
        public function __construct(array $parameters) {
            $this->parameters = $parameters;
        }
	    
	    /**
	     * Returns all parameters
	     * @return array<string, mixed>
	     */
	    public function getParameters(): array {
		    return $this->parameters;
	    }
	    
	    /**
         * Returns the table name
         * @return string
         */
        public function getName(): string {
            return $this->parameters["value"];
        }
    }