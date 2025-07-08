<?php
    
    namespace Quellabs\Canvas\Annotations;
    
    use Quellabs\AnnotationReader\AnnotationInterface;
    
    class AfterFilter implements AnnotationInterface {
        
        protected array $parameters;
	    
	    
        /**
         * Table constructor.
         * @param array $parameters
         */
        public function __construct(array $parameters) {
            $this->parameters = $parameters;
        }
	    
	    /**
	     * Returns all parameters
	     * @return array
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