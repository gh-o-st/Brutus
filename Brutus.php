<?php namespace Brutus;

use Brutus\BrutusConfig;
/**
 * The Brutus class provides a suite of methods to evaluate the strength
 * of passwords against various security criteria. These criteria include
 * checks for minimum length, presence of uppercase, lowercase, numbers,
 * special characters, as well as entropy and resistance to brute force attacks.
 * 
 * Usage:
 * $brutus = new Brutus();
 * $brutus->setPw('YourPassword123!');
 * $isValid = $brutus->testAll();
 * 
 * @author Joshua Jones
 * @version 2.1
 * @package Brutus
 * 
 * @property-read BrutusConfig $config  The configuration instance with password strength rules.
 * @property-read array $charSets       A collection of character sets used for the brute force simulation.
 */
class Brutus {

    private string $pw;
    protected $charSets = array(
        "0123456789", #numeric
        "0123456789 ", #numeric + space
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ", #UPPERCASE
        "abcdefghijklmnopqrstuvwxyz", #lowercase
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ ", #UPPERCASE + space
        "abcdefghijklmnopqrstuvwxyz ", #lowercase + space
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", #UPPERCASE alphanumeric
        "abcdefghijklmnopqrstuvwxyz0123456789", #lowercase alphanumeric
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ", #UPPERCASE alphanumeric + space
        "abcdefghijklmnopqrstuvwxyz0123456789 ", #lowercase alphanumeric + space
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", #MIXEDcase
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ", #MIXEDcase alpha + space
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", #MIXEDcase alphanumeric
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ", #MIXEDcase alphanumeric + space
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+ ", #MIXEDcase alphanumeric + primary symbols
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]\"{}|;':,./<>?`~ " #MIXEDcase alphanumeric + all symbols
    );
    public BrutusConfig $config;

    public function __construct() {
        $this->config = BrutusConfig::getInstance();
    }

    public function setPw( string $pw ) {
        $this->pw = $pw;
    }

    public function testLength(): bool {
        if ( strlen( $this->pw ) < $this->config->getRules()['length'] ) {
            return false;
        }
        return true;
    }

    public function testLowercase(): bool {
        if ( $this->config->getRules()['lowercase']['enabled'] ) {
            $lowercase = preg_match_all( '/[a-z]/', $this->pw );
            if ( $lowercase < $this->config->getRules()['lowercase']['lowercase'] ) {
                return false;
            }
        }
        return true;
    }

    public function testUppercase(): bool {
        if ( $this->config->getRules()['uppercase']['enabled'] ) {
            $uppercase = preg_match_all( '/[A-Z]/', $this->pw );
            if ( $uppercase < $this->config->getRules()['uppercase']['uppercase'] ) {
                return false;
            }
        }
        return true;
    }

    public function testNumbers(): bool {
        if ( $this->config->getRules()['numbers']['enabled'] ) {
            $numbers = preg_match_all( '/[0-9]/', $this->pw );
            if ( $numbers < $this->config->getRules()['numbers']['numbers'] ) {
                return false;
            }
        }
        return true;
    }

    public function testSpecialChars(): bool {
        if ( $this->config->getRules()['specialchars']['enabled'] ) {
            $specialchars = preg_match_all( '/[^a-zA-Z0-9]/', $this->pw );
            if ( $specialchars < $this->config->getRules()['specialchars']['specialchars'] ) {
                return false;
            }
        }
        return true;
    }

    public function testEntropy(): bool {
        $entropy = $this->nistEntropy();
        if ( $entropy < $this->config->getRules()['entropy'] ) {
            return false;
        }
        return true;
    }

    public function testBruteForce(): bool {
        $days = $this->simulateAttack();
        if ( $days < $this->config->getRules()['bruteForce']['days'] ) {
            return false;
        }
        return true;
    }

    public function testLeaked(): bool {
        if ( $this->config->getRules()['leaked']['enabled'] ) {
            $leaked = $this->passLeaked( $this->config->getRules()['leaked']['startLine'], $this->config->getRules()['leaked']['endLine'] );
            if ( $leaked ) {
                return false;
            }
        }
        return true;
    }

    public function testPII( array $pii_tokens ): bool {
        if ( $this->config->getRules()['pii']['enabled'] ) {
            $tokens = $this->personalTokens( $pii_tokens );
            if ( count( $tokens ) > 0 ) {
                return false;
            }
        }
        return true;
    }

    public function testAll(): bool {
        return $this->testLength() &&
               $this->testLowercase() &&
               $this->testUppercase() &&
               $this->testNumbers() &&
               $this->testSpecialChars() &&
               $this->testEntropy() &&
               $this->testBruteForce() &&
               $this->testLeaked() &&
               $this->testPII( $this->config[ 'pii' ][ 'tokens' ] );
    }    

    /**
     * Use the original NIST algorithm for calculating password entropy.
     */
    private function originalNistEntropy(): float {

        $bits = 0;
        $pwLength = strlen( $this->pw );

        // Helper function to determine bits to add based on count
        $getBits = $this->bitsCalculator();

        for ( $cnt = 1; $cnt <= $pwLength; $cnt++ ) {
            $bits += $getBits( $cnt );
        }

        return $bits;
    }

    /**
     * Use the modified NIST algorithm for calculating password entropy 
     * based on diminishing returns for repeated characters.
     */
    private function diminishingNistEntropy(): float {

        $bits = 0;
        $pwLength = strlen( $this->pw );
        $char_arr = array_fill( 0, 256, 1 );

        $getBits = $this->bitsCalculator();

        for ( $cnt = 0; $cnt < $pwLength - 1; $cnt++ ) {

            $currentChar = ord( $this->pw[ $cnt ] );
            $nextChar = ord( $this->pw[ $cnt + 1 ] );

            if ( $currentChar === $nextChar ) {
                $char_arr[ $currentChar ] = $this->calculateMultiplier( $char_arr[ $currentChar ] );
            }

            $bits += $getBits( $cnt + 1, $char_arr[ $currentChar ] );
        }

        // Add the bits for the last character since we didn't check it in the loop
        $bits += $getBits( $pwLength, $char_arr[ ord( $this->pw[ -1 ] ) ] );

        return $bits;
    }

    /**
     * Returns a function to calculate bits based on count and an optional modifier.
     */
    private function bitsCalculator(): callable {
        return function( $count, $modifier = 1 ): float {
            return match( true ) {
                $count == 1 => 4,
                $count > 1 && $count <= 8 => $modifier * 2,
                $count > 8 && $count <= 20 => $modifier * 1.5,
                default => $modifier
            };
        };
    }

    /**
     * Calculate the multiplier for the current character based on penalties.
     */
    private function calculateMultiplier( float $currentMultiplier ): float {
        $penalties = [ 0.75 => 0.75, 0.5625 => 0.375, 0.421875 => 0.1875 ];

        foreach ( $penalties as $threshold => $multiplier ) {
            if ( $currentMultiplier >= $threshold ) {
                return $currentMultiplier * $multiplier;
            }
        }

        return $currentMultiplier;
    }

    // In the calling function or method, you can then do:
    private function nistEntropy(): float {
        if ( !$this->config[ 'bruteForce' ][ 'diminishing' ] ) {
            return $this->originalNistEntropy();
        }

        return $this->diminishingNistEntropy();
    }

    /**
     * Simulate a brute force attack to estimate the number of days
     * required to guess the given password using a specific hash rate profile.
     *
     * @return int Number of days to crack the password.
     */
    private function simulateAttack() {
        $compositeSet = $this->buildCompositeSet();
        $attempts = $this->calculateAttempts( $compositeSet );
        $days = $this->estimateCrackDays( $attempts );

        // Cap the maximum days to a billion for practicality.
        return min( $days, 1000000000 );
    }

    /**
     * Builds a composite character set from the given password.
     *
     * @return string Composite character set.
     */
    private function buildCompositeSet() {
        $compositeSet = '';

        foreach ( str_split( $this->pw ) as $char ) {
            $found = false;

            foreach ( $this->charSets as $characterSet ) {

                if ( strpos( $characterSet, $char ) !== false ) {
                    $compositeSet = $this->mergeCharSets( $compositeSet, $characterSet );
                    $found = true;
                    break;
                }

            }

            if ( !$found ) {
                // If a character isn't found in the predefined charsets,
                // default to the last charset for broadest search.
                return end( $this->charSets );
            }
        }

        return $compositeSet;
    }

    /**
     * Calculates the number of attempts to guess the password.
     *
     * @param string $compositeSet Composite character set.
     * @return string Total attempts (big number).
     */
    private function calculateAttempts( string $compositeSet ) {
        $attempts = '0';
        $charactersInBase = strlen( $compositeSet );
        $passwordLength = strlen( $this->pw );

        for ( $position = 0; $position < $passwordLength; $position++ ) {
            $powerOf = $passwordLength - $position - 1;
            $charAtPosition = strpos( $compositeSet, $this->pw[ $position ] );
            $multiplier = bcpow( $charactersInBase, $powerOf );
            $newAttempts = bcmul( $charAtPosition, $multiplier );
            $attempts = bcadd( $attempts, $newAttempts );
        }

        return $attempts;
    }

    /**
     * Estimates the number of days to crack the password with a brute force attack.
     *
     * @param string $attempts Number of attempts to guess the password.
     * @return int Number of days.
     */
    private function estimateCrackDays( int $attempts ) {
        $perDay = bcmul( $this->config['bruteForce']['profile'], 86400 );
        return (int) bcdiv( $attempts, $perDay );
    }
    
    /**
     * Merge two character sets into a single set without duplicates.
     *
     * @param string $set1 First character set.
     * @param string $set2 Second character set.
     * @return string Merged character set.
     */
    private function mergeCharSets( string $set1, string $set2 ): string {
        $combinedChars = str_split( $set1 . $set2 );
        return implode( '', array_unique( $combinedChars ) );
    }

    private function personalTokens($pii_tokens): array {
        $convertLeet = $this->config->getRules()['leet']['enabled'];
        
        if ($convertLeet) {
            $variants = $this->convertLeet();
        } else {
            $variants = [$this->pw];
        }
    
        $tokens = [];
    
        foreach ( $variants as $variant ) {
            if ( in_array( $variant, $pii_tokens ) ) {
                $tokens[] = $variant;
            }
        }
    
        return $tokens; // return the matched tokens
    }
    

    private function convertLeet() {
        $map = $this->config->getLeetMap();
        
        $variants = [ $this->pw ]; // Start with original password

        foreach ( $map as $char => $substitutes ) {
            $newVariants = [];

            foreach ( $variants as $variant ) {
                foreach ( $substitutes as $substitute ) {
                    $newVariants[] = str_replace( $substitute, $char, $variant );
                }
            }

            $variants = array_merge( $variants, $newVariants );
        }

        $variants = array_unique( $variants ); // Remove any duplicates
        return $variants;
    }


    /**
     * Test the password against a subset of the list of the 10M most common passwords.
     * Users can select a subset of the list to test against (e.g., top 10,000 to 10M).
     * The password list is located at: src/Brutus/data/10M-leaked-passwords.txt
     *
     * @param int $startLine Starting line of the subset, default is 1 (first line).
     * @param int|null $endLine Ending line of the subset, default is null (will read to the end of file).
     * @return bool True if the password is found in the list, otherwise false.
     */
    private function passLeaked( int $startLine = 1, int $endLine = null ): bool {
        $filePath = 'src/Brutus/data/10M-leaked-passwords.txt';

        // Check if the file exists and is readable
        if ( !file_exists( $filePath ) || !is_readable( $filePath ) ) {
            throw new \Exception( 'Unable to read the password file.' );
        }

        $currentLineNumber = 1;
        $fileHandle = fopen( $filePath, 'r' );

        if ( $fileHandle ) {
            while ( ( $line = fgets( $fileHandle ) ) !== false ) {
                // If we've reached the end of the desired range, exit loop
                if ( $endLine !== null && $currentLineNumber > $endLine ) {
                    break;
                }

                // If we're within the desired range, check the password
                if ( $currentLineNumber >= $startLine ) {
                    $line = trim( $line );
                    if ( $line === $this->pw ) {
                        fclose( $fileHandle );
                        return true;
                    }
                }
                
                $currentLineNumber++;
            }
            fclose( $fileHandle );
        }

        return false;
    }


}