<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	class Date extends RulesBase {
		
		/**
         * Detects the date format in $string and returns it
         * @url https://stackoverflow.com/questions/43873454/identify-date-format-from-a-string-in-php
         * @param string $date
         * @return string|bool
         */
        protected function dateExtractFormat(string $date): bool|string {
            // check Day -> (0[1-9]|[1-2][0-9]|3[0-1])
            // check Month -> (0[1-9]|1[0-2])
            // check Year -> [0-9]{4} or \d{4}
            
            $patterns = [
                '/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3,8}Z\b/'     => 'Y-m-d\TH:i:s.u\Z', // format DATE ISO 8601
                '/\b\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])\b/' => 'Y-m-d',
                '/\b\d{4}-(0[1-9]|[1-2][0-9]|3[0-1])-(0[1-9]|1[0-2])\b/' => 'Y-d-m',
                '/\b([1-9]|[1-2][0-9]|3[0-1])-([1-9]|1[0-2])-\d{4}\b/'   => 'd-m-Y',
                '/\b(0[1-9]|[1-2][0-9]|3[0-1])-(0[1-9]|1[0-2])-\d{4}\b/' => 'd-m-Y',
                '/\b(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])-\d{4}\b/' => 'm-d-Y',
                
                '/\b\d{4}\/(0[1-9]|[1-2][0-9]|3[0-1])\/(0[1-9]|1[0-2])\b/' => 'Y/d/m',
                '/\b\d{4}\/(0[1-9]|1[0-2])\/(0[1-9]|[1-2][0-9]|3[0-1])\b/' => 'Y/m/d',
                '/\b(0[1-9]|[1-2][0-9]|3[0-1])\/(0[1-9]|1[0-2])\/\d{4}\b/' => 'd/m/Y',
                '/\b(0[1-9]|1[0-2])\/(0[1-9]|[1-2][0-9]|3[0-1])\/\d{4}\b/' => 'm/d/Y',
                
                '/\b\d{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[1-2][0-9]|3[0-1])\b/'    => 'Y.m.d',
                '/\b\d{4}\.(0[1-9]|[1-2][0-9]|3[0-1])\.(0[1-9]|1[0-2])\b/'    => 'Y.d.m',
                '/\b(0[1-9]|[1-2][0-9]|3[0-1])\.(0[1-9]|1[0-2])\.\d{4}\b/'    => 'd.m.Y',
                '/\b(0[1-9]|1[0-2])\.(0[1-9]|[1-2][0-9]|3[0-1])\.\d{4}\b/'    => 'm.d.Y',
                
                // for 24-hour | hours seconds
                '/\b(?:2[0-3]|[01][0-9]):[0-5][0-9](:[0-5][0-9])\.\d{3,6}\b/' => 'H:i:s.u',
                '/\b(?:2[0-3]|[01][0-9]):[0-5][0-9](:[0-5][0-9])\b/'          => 'H:i:s',
                '/\b(?:2[0-3]|[01][0-9]):[0-5][0-9]\b/'                       => 'H:i',
                
                // for 12-hour | hours seconds
                '/\b(?:1[012]|0[0-9]):[0-5][0-9](:[0-5][0-9])\.\d{3,6}\b/'    => 'h:i:s.u',
                '/\b(?:1[012]|0[0-9]):[0-5][0-9](:[0-5][0-9])\b/'             => 'h:i:s',
                '/\b(?:1[012]|0[0-9]):[0-5][0-9]\b/'                          => 'h:i',
                
                '/\.\d{3}\b/' => '.v'
            ];
            
            $result = preg_replace(array_keys($patterns), array_values($patterns), $date);
            return ($result != $date) ? $result : false;
        }
        
		public function validate(mixed $value): bool {
            if (($value === "") || is_null($value)) {
                return true;
            }
            
            return $this->dateExtractFormat($value) !== false;
		}
		
		public function getError(): string {
			if (is_null($this->message)) {
				return "This value is not a valid date.";
			}
			
			return $this->message;
		}
	}