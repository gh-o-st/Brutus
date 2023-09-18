<?php namespace Brutus;
/**
 * The BrutusConfig class defines configuration rules for password strength and validation.
 *
 * This class allows for the creation of configuration instances that can be used to 
 * define password requirements such as minimum length, character class requirements,
 * entropy constraints, and brute force considerations.
 *
 * Example Usage:
 * 
 * ```php
 * $brutus = new Brutus();
 * $config = $brutus->config
 *              ->setLengthRule(12)
 *              ->setLowercaseRule(true, 2)
 *              ->setUppercaseRule(true, 2)
 *              ->setNumbersRule(true, 2)
 *              ->setSymbolsRule(true, 2, ['!', '@', '#'])
 *              ->setEntropyRule(true, 40, true)
 *              ->setBruteForceRule(true, 'medium', 60);
 * ```
 *
 * Note: 
 * - Direct instantiation of this class is prevented. Use `getInstance()` to create a configuration object.
 * - For each rule, the first argument usually determines if the rule is enabled or not.
 *
 * Rules:
 * - `setLengthRule(int $length)`: Defines a minimum length for the password.
 * - `setLowercaseRule(bool $enable, int $lowercase)`: Sets a requirement for lowercase characters.
 * - `setUppercaseRule(bool $enable, int $uppercase)`: Sets a requirement for uppercase characters.
 * - `setNumbersRule(bool $enable, int $numbers)`: Sets a requirement for numerical characters.
 * - `setSymbolsRule(bool $enable, int $symbols, ?array $customList)`: Sets a requirement for symbol characters, with an optional custom symbol list.
 * - `setEntropyRule(bool $enable, int $entropy, bool $diminishing)`: Specifies a minimum entropy requirement, with an option to account for diminishing returns for repeated characters.
 * - `setBruteForceRule(bool $enable, string $profile, int $days)`: Determines how long (in days) the password should withstand a brute force attack, based on a specified profile (low, medium, high, dedicated).
 * 
 * @author Joshua Jones
 * @version 2.1
 */


class BrutusConfig {

    private array $rules = [];

    // Making the constructor private to prevent direct instantiation
    private function __construct() {

    }

    // Provide a static method to get an instance
    public static function getInstance(): BrutusConfig {
        return new self();
    }

    public function getRules(): array {
        return $this->rules;
    }

    public function setLengthRule( int $length ) {
        if ( $length < 10 ) {
            throw new \Exception( 'Password must be at least 10 characters long.' );
        }
        $this->rules['length'] = $length;
    }

    public function setLowercaseRule( bool $enable, int $lowercase ) {
        if ( $enable ) {
            if ( $lowercase < 1 ) {
                throw new \Exception( 'Password must contain at least 1 lowercase letter.' );
            }
        }
        $this->rules['lowercase'] = [
            'enabled' => $enable,
            'lowercase' => $lowercase
        ];
    }

    public function setUppercaseRule( bool $enable, int $uppercase ) {
        if ( $enable ) {
            if ( $uppercase < 1 ) {
                throw new \Exception( 'Password must contain at least 1 uppercase letter.' );
            }
        }
        $this->rules['uppercase'] = [
            'enabled' => $enable,
            'uppercase' => $uppercase
        ];
    }

    public function setNumbersRule( bool $enable, int $numbers ) {
        if ( $enable ) {
            if ( $numbers < 1 ) {
                throw new \Exception( 'Password must contain at least 1 number.' );
            }
        }
        $this->rules['numbers'] = [
            'enabled' => $enable,
            'numbers' => $numbers
        ];
    }

    public function setSymbolsRule( bool $enable, int $symbols, ?array $customList = null ) {
        if ( $enable ) {
            if ( !is_int( $symbols ) ) {
                throw new \Exception( 'Invalid symbols rule. Symbols must be an integer.' );
            }
            if ( $symbols < 1 ) {
                throw new \Exception( 'Password must contain at least 1 symbol.' );
            }
            if ( $customList !== null ) {
                if ( !is_array( $customList ) ) {
                    throw new \Exception( 'Invalid symbols rule. Custom list must be an array.' );
                }
                if ( count( $customList ) < 1 ) {
                    throw new \Exception( 'Symbol rule requires at least 1 symbol.' );
                }
            }
        }
        $this->rules['symbols'] = [
            'enabled' => $enable,
            'symbols' => $symbols,
            'customList' => $customList
        ];
    }

    public function setEntropyRule( bool $enable, int $entropy, bool $diminishing = false ) {
        if ( $enable ) {
            if ( !is_int( $entropy ) ) {
                throw new \Exception( 'Invalid entropy rule. Entropy must be an integer.' );
            }
            if ( $entropy < 30 ) {
                throw new \Exception( 'Password must contain at least 30 bits of entropy.' );
            }
        }
        $this->rules['entropy'] = [
            'enabled' => $enable,
            'entropy' => $entropy,
            'diminishing' => $diminishing
        ];
    }

    public function setBruteForceRule( bool $enable, string $profile, int $days ) {
        
        if ( $enable ) {
            if ( $days < 30 ) {
                throw new \Exception( 'Even a highschool kid has enough patience to wait a month...' );
            }
            if ( !in_array( strtolower( trim( $profile ) ), [ 'low', 'medium', 'high', 'dedicated' ] ) ) {
                throw new \Exception( 'Invalid profile. Allowed profiles are: low, medium, high, dedicated.' );
            }
        }
    
        $profileValue = match( strtolower( trim( $profile ) ) ) {
            'low' => 1000000,
            'medium' => 10000000000,
            'high' => 100000000000000,
            'dedicated' => 1000000000000000000,
        };
        
        $this->rules['bruteForce'] = [
            'enabled' => $enable,
            'profile' => $profileValue,
            'days' => $days
        ];
    }

    public function getLeetMap(): array {
        return [
            'a' => [ '4', '@' ],
            'b' => [ '8' ],
            'c' => [ '(', '{', '[', '<' ],
            'd' => [ '6' ],
            'e' => [ '3' ],
            'f' => [ '#' ],
            'g' => [ '9' ],
            'h' => [ '#' ],
            'i' => [ '1', '!', '|' ],
            'j' => [ '7' ],
            'k' => [ 'X' ],
            'l' => [ '1', '!', '|' ],
            'o' => [ '0' ],
            's' => [ '5', '$' ],
            't' => [ '7' ],
            'x' => [ '><' ],
            'z' => [ '2' ]
        ];
    }
    
}