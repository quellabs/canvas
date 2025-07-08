<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	class Zipcode extends RulesBase {
		
		
		/**
		 * List of zipcode formats per country (ISO2)
		 * @var array
		 */
		protected array $m_zipcode_format;
		
		/**
		 * Country ISO2 code to check
		 * @var string
		 */
		protected string $countryIso2;
		
		/**
		 * Zipcode constructor
		 * @param string $countryIso2
		 * @param string|null $message
		 */
		public function __construct(string $countryIso2="NL", ?string $message=null) {
			parent::__construct($message);
			$this->countryIso2 = $countryIso2;
			
			/**
			 * country code: ISO 3166 2-letter code
			 * format:
			 *     # - numberic 0-9
			 *     @ - alpha a-zA-Z
			 */
			$this->m_zipcode_format = [
				'AC' => array(),                            # Ascension
				'AD' => array('AD###', '#####'),            # ANDORRA
				'AE' => array(),                            # UNITED ARAB EMIRATES
				'AF' => array('####'),                      # AFGHANISTAN
				'AG' => array(),                            # ANTIGUA AND BARBUDA
				'AI' => array('AI-2640'),                   # ANGUILLA
				'AL' => array('####'),                      # ALBANIA
				'AM' => array('####'),                      # ARMENIA
				'AN' => array(),                            # NETHERLANDS ANTILLES
				'AO' => array(),                            # ANGOLA
				'AQ' => array('BIQQ 1ZZ'),                  # ANTARCTICA
				'AR' => array('####', '@####@@@'),          # ARGENTINA
				'AS' => array('#####', '#####-####'),       # AMERICAN SAMOA
				'AT' => array('####'),                      # AUSTRIA
				'AU' => array('####'),                      # AUSTRALIA
				'AW' => array(),                            # ARUBA
				'AX' => array('#####', 'AX-#####'),         # Åland
				'AZ' => array('AZ ####'),                   # AZERBAIJAN
				'BA' => array('#####'),                     # BOSNIA AND HERZEGOWINA
				'BB' => array('BB#####'),                   # BARBADOS
				'BD' => array('####'),                      # BANGLADESH
				'BE' => array('####'),                      # BELGIUM
				'BF' => array(),                            # BURKINA FASO
				'BG' => array('####'),                      # BULGARIA
				'BH' => array('###', '####'),               # BAHRAIN
				'BI' => array(),                            # BURUNDI
				'BJ' => array(),                            # BENIN
				'BL' => array('#####'),                     # Sankt Bartholomäus
				'BM' => array('@@ ##', '@@ @@'),            # BERMUDA
				'BN' => array('@@####'),                    # BRUNEI DARUSSALAM
				'BO' => array(),                            # BOLIVIA
				'BQ' => array(),                            # Karibische Niederlande
				'BR' => array('#####-###', '#####'),        # BRAZIL
				'BS' => array(),                            # BAHAMAS
				'BT' => array('#####'),                     # BHUTAN
				'BV' => array(),                            # BOUVET ISLAND
				'BW' => array(),                            # BOTSWANA
				'BY' => array('######'),                    # BELARUS
				'BZ' => array(),                            # BELIZE
				'CA' => array('@#@ #@#'),                   # CANADA
				'CC' => array('####'),                      # COCOS (KEELING) ISLANDS
				'CD' => array(),                            # CONGO, Democratic Republic of (was Zaire)
				'CF' => array(),                            # CENTRAL AFRICAN REPUBLIC
				'CG' => array(),                            # CONGO, People's Republic of
				'CH' => array('####'),                      # SWITZERLAND
				'CI' => array(),                            # COTE D'IVOIRE
				'CK' => array(),                            # COOK ISLANDS
				'CL' => array('#######', '###-####'),       # CHILE
				'CM' => array(),                            # CAMEROON
				'CN' => array('######'),                    # CHINA
				'CO' => array('######'),                    # COLOMBIA
				'CR' => array('#####', '#####-####'),       # COSTA RICA
				'CU' => array('#####'),                     # CUBA
				'CV' => array('####'),                      # CAPE VERDE
				'CW' => array(),                            # Curaçao
				'CX' => array('####'),                      # CHRISTMAS ISLAND
				'CY' => array('####'),                      # Cyprus
				'CZ' => array('### ##'),                    # Czech Republic
				'DE' => array('#####'),                     # GERMANY
				'DJ' => array(),                            # DJIBOUTI
				'DK' => array('####'),                      # DENMARK
				'DM' => array(),                            # DOMINICA
				'DO' => array('#####'),                     # DOMINICAN REPUBLIC
				'DZ' => array('#####'),                     # ALGERIA
				'EC' => array('######'),                    # ECUADOR
				'EE' => array('#####'),                     # ESTONIA
				'EG' => array('#####'),                     # EGYPT
				'EH' => array(),                            # WESTERN SAHARA
				'ER' => array(),                            # ERITREA
				'ES' => array('#####'),                     # SPAIN
				'ET' => array('####'),                      # ETHIOPIA
				'FI' => array('#####'),                     # FINLAND
				'FJ' => array(),                            # FIJI
				'FK' => array('FIQQ 1ZZ'),                  # FALKLAND ISLANDS (MALVINAS)
				'FM' => array('#####', '#####-####'),       # MICRONESIA
				'FO' => array('###'),                       # FAROE ISLANDS
				'FR' => array('#####'),                     # FRANCE
				'FX' => array(),                            # FRANCE, METROPOLITAN
				'GA' => array(),                            # GABON
				'GB' => array('@@## #@@', '@#@ #@@', '@@# #@@', '@@#@ #@@', '@## #@@', '@# #@@'), # UK
				'GD' => array(),                            # GRENADA
				'GE' => array('####'),                      # GEORGIA
				'GF' => array('973##'),                     # FRENCH GUIANA
				'GG' => array('GY# #@@', 'GY## #@@'),       # Guernsey
				'GH' => array(),                            # GHANA
				'GI' => array('GX11 1AA'),                  # GIBRALTAR
				'GL' => array('####'),                      # GREENLAND
				'GM' => array(),                            # GAMBIA
				'GN' => array('###'),                       # GUINEA
				'GP' => array('971##'),                     # GUADELOUPE
				'GQ' => array(),                            # EQUATORIAL GUINEA
				'GR' => array('### ##'),                    # GREECE
				'GS' => array('SIQQ 1ZZ'),                  # SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS
				'GT' => array('#####'),                     # GUATEMALA
				'GU' => array('#####', '#####-####'),       # GUAM
				'GW' => array('####'),                      # GUINEA-BISSAU
				'GY' => array(),                            # GUYANA
				'HK' => array(),                            # HONG KONG
				'HM' => array(),                            # HEARD AND MC DONALD ISLANDS
				'HN' => array('@@####', '#####'),           # HONDURAS
				'HR' => array('#####'),                     # CROATIA
				'HT' => array('####'),                      # HAITI
				'HU' => array('####'),                      # HUNGARY
				'IC' => array('#####'),                     # THE CANARY ISLANDS
				'ID' => array('#####'),                     # INDONESIA
				'IE' => array('@** ****'),                  # IRELAND
				'IL' => array('#######'),                   # ISRAEL
				'IM' => array('IM# #@@', 'IM## #@@'),       # Isle of Man
				'IN' => array('######', '### ###'),         # INDIA
				'IO' => array('BBND 1ZZ'),                  # BRITISH INDIAN OCEAN TERRITORY
				'IQ' => array('#####'),                     # IRAQ
				'IR' => array('##########', '#####-#####'), # IRAN
				'IS' => array('###'),                       # ICELAND
				'IT' => array('#####'),                     # ITALY
				'JE' => array('JE# #@@', 'JE## #@@'),       # Jersey
				'JM' => array('##'),                        # JAMAICA
				'JO' => array('#####'),                     # JORDAN
				'JP' => array('###-####', '###'),           # JAPAN
				'KE' => array('#####'),                     # KENYA
				'KG' => array('######'),                    # KYRGYZSTAN
				'KH' => array('#####'),                     # CAMBODIA
				'KI' => array(),                            # KIRIBATI
				'KM' => array(),                            # COMOROS
				'KN' => array(),                            # SAINT KITTS AND NEVIS
				'KP' => array(),                            # NORTH KOREA
				'KR' => array('###-###', '#####'),          # SOUTH KOREA
				'KW' => array('#####'),                     # KUWAIT
				'KY' => array('KY#-####'),                  # CAYMAN ISLANDS
				'KZ' => array('######'),                    # KAZAKHSTAN
				'LA' => array('#####'),                     # LAO PEOPLE'S DEMOCRATIC REPUBLIC
				'LB' => array('#####', '#### ####'),        # LEBANON
				'LC' => array('LC## ###'),                  # SAINT LUCIA
				'LI' => array('####'),                      # LIECHTENSTEIN
				'LK' => array('#####'),                     # SRI LANKA
				'LR' => array('####'),                      # LIBERIA
				'LS' => array('###'),                       # LESOTHO
				'LT' => array('LT-#####', '#####'),         # LITHUANIA
				'LU' => array('####'),                      # LUXEMBOURG
				'LV' => array('LV-####'),                   # LATVIA
				'LY' => array(),                            # LIBYAN ARAB JAMAHIRIYA
				'MA' => array('#####'),                     # MOROCCO
				'MC' => array('980##'),                     # MONACO
				'MD' => array('MD####', 'MD-####'),         # MOLDOVA
				'ME' => array('#####'),                     # MONTENEGRO
				'MF' => array('97150'),                     # Saint-Martin
				'MG' => array('###'),                       # MADAGASCAR
				'MH' => array('#####', '#####-####'),       # MARSHALL ISLANDS
				'MK' => array('####'),                      # MACEDONIA
				'ML' => array(),                            # MALI
				'MM' => array('#####'),                     # MYANMAR
				'MN' => array('#####'),                     # MONGOLIA
				'MO' => array(),                            # MACAU
				'MP' => array('#####', '#####-####'),       # SAIPAN, NORTHERN MARIANA ISLANDS
				'MQ' => array('972##'),                     # MARTINIQUE
				'MR' => array(),                            # MAURITANIA
				'MS' => array(),                            # MONTSERRAT
				'MT' => array('@@@ ####'),                  # MALTA
				'MU' => array('#####'),                     # MAURITIUS
				'MV' => array('#####'),                     # MALDIVES
				'MW' => array(),                            # MALAWI
				'MX' => array('#####'),                     # MEXICO
				'MY' => array('#####'),                     # MALAYSIA
				'MZ' => array('####'),                      # MOZAMBIQUE
				'NA' => array(),                            # NAMIBIA
				'NC' => array('988##'),                     # NEW CALEDONIA
				'NE' => array('####'),                      # NIGER
				'NF' => array('####'),                      # NORFOLK ISLAND
				'NG' => array('######'),                    # NIGERIA
				'NI' => array('#####'),                     # NICARAGUA
				'NL' => array('####@@', '#### @@'),         # NETHERLANDS
				'NO' => array('####'),                      # NORWAY
				'NP' => array('#####'),                     # NEPAL
				'NR' => array(),                            # NAURU
				'NU' => array(),                            # NIUE
				'NZ' => array('####'),                      # NEW ZEALAND
				'OM' => array('###'),                       # OMAN
				'PA' => array('####'),                      # PANAMA
				'PE' => array('#####', 'PE #####'),         # PERU
				'PF' => array('987##'),                     # FRENCH POLYNESIA
				'PG' => array('###'),                       # PAPUA NEW GUINEA
				'PH' => array('####'),                      # PHILIPPINES
				'PK' => array('#####'),                     # PAKISTAN
				'PL' => array('##-###'),                    # POLAND
				'PM' => array('97500'),                     # ST. PIERRE AND MIQUELON
				'PN' => array('PCRN 1ZZ'),                  # PITCAIRN
				'PR' => array('#####', '#####-####'),       # PUERTO RICO
				'PS' => array('###'),                       # PALESTINIAN TERRITORY
				'PT' => array('####-###'),                  # PORTUGAL
				'PW' => array('#####', '#####-####'),       # PALAU
				'PY' => array('####'),                      # PARAGUAY
				'QA' => array(),                            # QATAR
				'RE' => array('974##'),                     # REUNION
				'RO' => array('######'),                    # ROMANIA
				'RS' => array('#####'),                     # SERBIA
				'RU' => array('######'),                    # RUSSIA
				'RW' => array(),                            # RWANDA
				'SA' => array('#####', '#####-####'),       # SAUDI ARABIA
				'SB' => array(),                            # SOLOMON ISLANDS
				'SC' => array(),                            # SEYCHELLES
				'SD' => array('#####'),                     # SUDAN
				'SE' => array('### ##'),                    # SWEDEN
				'SG' => array('######'),                    # SINGAPORE
				'SH' => array('@@@@ 1ZZ'),                  # ST. HELENA
				'SI' => array('####', 'SI-####'),           # SLOVENIA
				'SJ' => array('####'),                      # SVALBARD AND JAN MAYEN ISLANDS
				'SK' => array('### ##'),                    # SLOVAKIA
				'SL' => array(),                            # SIERRA LEONE
				'SM' => array('4789#'),                     # SAN MARINO
				'SN' => array('#####'),                     # SENEGAL
				'SO' => array('@@ #####'),                  # SOMALIA
				'SR' => array(),                            # SURINAME
				'SS' => array('#####'),                     # SOUTH SUDAN
				'ST' => array(),                            # SAO TOME AND PRINCIPE
				'SV' => array('####'),                      # EL SALVADOR
				'SX' => array(),                            # Sint Maarten
				'SY' => array(),                            # SYRIAN ARAB REPUBLIC
				'SZ' => array('@###'),                      # SWAZILAND
				'TA' => array(),                            # Tristan da Cunha
				'TC' => array('TKCA 1ZZ'),                  # TURKS AND CAICOS ISLANDS
				'TD' => array(),                            # CHAD
				'TF' => array(),                            # FRENCH SOUTHERN TERRITORIES
				'TG' => array(),                            # TOGO
				'TH' => array('#####'),                     # THAILAND
				'TJ' => array('######'),                    # TAJIKISTAN
				'TK' => array(),                            # TOKELAU
				'TL' => array(),                            # EAST TIMOR
				'TM' => array('######'),                    # TURKMENISTAN
				'TN' => array('####'),                      # TUNISIA
				'TO' => array(),                            # TONGA
				'TR' => array('#####'),                     # TURKEY
				'TT' => array('######'),                    # TRINIDAD AND TOBAGO
				'TV' => array(),                            # TUVALU
				'TW' => array('###', '###-##'),             # TAIWAN
				'TZ' => array('#####'),                     # TANZANIA
				'UA' => array('#####'),                     # UKRAINE
				'UG' => array(),                            # UGANDA
				'UM' => array(),                            # UNITED STATES MINOR OUTLYING ISLANDS
				'US' => array('#####', '#####-####'),       # USA
				'UY' => array('#####'),                     # URUGUAY
				'UZ' => array('######'),                    # USBEKISTAN
				'VA' => array('00120'),                     # VATICAN CITY STATE
				'VC' => array('VC####'),                    # SAINT VINCENT AND THE GRENADINES
				'VE' => array('####', '####-@'),            # VENEZUELA
				'VG' => array('VG####'),                    # VIRGIN ISLANDS (BRITISH)
				'VI' => array('#####', '#####-####'),       # VIRGIN ISLANDS (U.S.)
				'VN' => array('######'),                    # VIETNAM
				'VU' => array(),                            # VANUATU
				'WF' => array('986##'),                     # WALLIS AND FUTUNA ISLANDS
				'WS' => array('WS####'),                    # SAMOA
				'YE' => array(),                            # YEMEN
				'YT' => array('976##'),                     # MAYOTTE
				'ZA' => array('####'),                      # SOUTH AFRICA
				'ZM' => array('#####'),                     # ZAMBIA
				'ZW' => array(),                            # ZIMBABWE
				'XK' => array('#####'),                     # KOSOVO
			];
		}
		
		/**
		 * Transform zipcode pattern to a regular expression
		 * @param string $format
		 * @param bool $ignoreSpaces
		 * @return string
		 */
		protected function getFormatPattern(string $format, bool $ignoreSpaces = false): string {
			$pattern = str_replace('#', '\d', $format);
			$pattern = str_replace('@', '[a-zA-Z]', $pattern);
			$pattern = str_replace('*', '[a-zA-Z0-9]', $pattern);
			
			if ($ignoreSpaces) {
				$pattern = str_replace(' ', ' ?', $pattern);
			}
			
			return '/^' . $pattern . '$/';
		}
		
		/**
		 * Returns true if the zipcode is correctly formatted for the given country, false if not
		 * @url https://github.com/sirprize/postal-code-validator/blob/master/src/Validator.php
		 * @param string $countryIsoCode2
		 * @param string $postalCode
		 * @param bool $ignoreSpaces
		 * @return bool
		 */
		protected function isZipcodeValid(string $countryIsoCode2, string $postalCode, bool $ignoreSpaces = true): bool {
			if (isset($this->m_zipcode_format[$countryIsoCode2])) {
				$thePostalCode = trim($postalCode);
				
				foreach ($this->m_zipcode_format[$countryIsoCode2] as $format) {
					if (preg_match($this->getFormatPattern($format, $ignoreSpaces), $thePostalCode)) {
						return true;
					}
				}
				
				if (!count($this->m_zipcode_format[$countryIsoCode2])) {
					return true;
				}
			}
			
			return false;
		}
		
		public function validate(mixed $value): bool {
			// no value, nothing to check
            if (($value === "") || is_null($value)) {
                return true;
            }

			// Check zipcode format
			return $this->isZipcodeValid($this->countryIso2, $value);
		}
		
		public function getError(): string {
			if (is_null($this->message)) {
				return "This value is not a valid zipcode.";
			}
			
			return $this->message;
		}
	}