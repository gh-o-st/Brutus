<?php

/**
* Brutus - Comprehensive password testing made easy
*
* A simple, yet comprehensive password grading and validation class which
* utilizes tried and tested methods for quantifying a password's strength
* as well as enforcing a security policy condusive to strong passwords.
*
* Includes a dictionary of the 10k most common passwords from Mike Burnett
* (https:#xato.net/passwords/more-top-worst-passwords) as well as an extensive
* alphabetical dictionary of common terms. Checking passwords against a library
* like this helps to prevent users from choosing passwords that wouldn't stand
* up to even the simplest dictionary attacks. We also check the password for
* "leetspeak" substitutions. While on the surface they may seem to make the
* password stronger, their predictability actually makes it so that they do
* little more for your password than using plain text characters.
*
* By combining the methods above with methods to measure the shannon entropy
* of the password as well as simulating a brute force attack, we can more
* accurately measure/grade the "strength" of a given password. This can help
* you to implement a more secure password policy by disallowing weak passwords
* that wouldn't stand up to brute force attacks.
*
*
* @author Josh Jones
* @version 1.0
* @license GPL3
*
*
*
* Example Usage:
* * * * * * * * *
* $brutus = new Brutus($args);
*
* if ($brutus->badPass($password, $id)) {
*   foreach ($brutus->showErrors() as $error) {
*     echo $error.'<br>';
*   }
* }
*
*/

class Brutus {

  /**
   * @var string $password Set to null at start, use param of primary method to modify
   */
  protected $password = null;

  /**
   * @var int $passlen The length of the password currently being tested
   */
  protected $passlen = 0;

  /**
   * @var integer $hashpsec The simulated speed of attacker's system represented by
   * how many hashes it can crank out per second. 1 billion by default (worst case)
   */
  private $hashpsec = 1000000000;

  /**
   * @var string $commons The relative file path of the common password file to be used
   */
  private $commons = 'commons.txt';

  /**
   * @var array $passlist An array of all possible permutations of a "leet" password
   */
  protected $passlist = array();

  /**
   * @var array $rules An array of rules to govern how we should grade a password
   * (passed as parameter in the __construct() method)
   */
  protected $rules = array();

  /**
   * @var array $errors This array will be filled with entries if any errors are found
   * during the grading of each password.
   */
  protected $errors = array();

  /**
   * @var bool $breakout Efficiency tweak that governs whether or not to break out of a 
   * function upon encountering the first error during processing. (modified in testsPassed() method)
   */
  protected $breakout = true;

  /**
   * @var array $msgs A list of strings to be matched to each $errors type
   */
  protected $msgs = array(
    'brute' => 'Password must survive %s days of brute force attempts; Currently at %s',
    'upper' => 'Password must contain at least %s uppercase letter%s',
    'lower' => 'Password must contain at least %s lowercase leter%s',
    'minlen' => 'Password cannot be less than %s characters',
    'maxlen' => 'Password cannot be greater than %s characters',
    'number' => 'Password must contain at least %s number%s',
    'special' => 'Password must contain at least %s special character%s',
    'entropy' => 'Password must have at least %s bits of entropy; Currently at %s',
    'commons' => 'Password was found in the list of most common passwords',
    'identity' => 'Password contains one or more personally identifiable tokens'
  );

  /**
   * @var array $charSets All possible character sets used in password(s) starting with simplest
   *
   * We start with the simplest character set (all numeric), and slowly work our way up increasing
   * the complexity of the character set gradually so as to err in the attacker's favor by reducing
   * the estimated keyspace needed to crack a particular password using brute force.
   */
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

  /**
   * @param array $args The list of optional arguments which will be assigned to the $rules array
   * @param mixed $msgs Set to NULL by default. If not null, should contain array to replace original strings
   * @throws Exception If $msgs array does not contain the correct number of entries
   */
  public function __construct($args=array()) {

    /*
     *****************************************************************************************
     *            _  _ ___ ___ ___   ___ ___   ___  ___    _   ___  ___  _  _ ___            *
     *           | || | __| _ \ __| | _ ) __| |   \| _ \  /_\ / __|/ _ \| \| / __|           *
     *           | __ | _||   / _|  | _ \ _|  | |) |   / / _ \ (_ | (_) | .` \__ \           *
     *           |_||_|___|_|_\___| |___/___| |___/|_|_\/_/ \_\___|\___/|_|\_|___/           *
     *                                                                                       *
     *****************************************************************************************
    */

    # Setup the default options
    $defaults = array(
      'brute' => 60, # How long (in days) the password should survive a continued brute force attack
      'lower' => 2, # The number of lowercase letters required
      'upper' => 2, # The number of uppercase letters required
      'number' => 1, # The number of numeric characters required
      'minlen' => 10, # The minimum length of the password (less than 10 is strongly discouraged)
      'maxlen' => 50, # The maximum length of the password
      'lookup' => true, # Whether or not to check the password against the 10k most common
      'special' => 1, # The number of special characters required in the password
      'entropy' => 30, # The number of entropic bits the password must have
      'usefile' => null, # Whether to use a physical file instead of a database
      'diminishing' => true # Whether to penalize a password for repetitive characters
    );

    # Check for custom configuration entries
    if (!empty($args)) {
      foreach ($args as $key => $val) {
        # WARNING!!! Dragons will eat your babies if you change this default fallback
        $this->rules[$key] = ($key == 'minlen' && $val < 10) ? 10 : $val;
      }
    }

    # Set remaining keys to default values
    foreach ($defaults as $key => $val) {
      if (!array_key_exists($key, $this->rules)) {
        $this->rules[$key] = $val;
      }
    }

    # Don't be a f***ing idiot... This should never happen.
    if ($this->rules['minlen'] > $this->rules['maxlen']) {
      throw new Exception("Min/Max Impossibility... World will self-destruct in 10 seconds.");
    }

    # The only way this exception will be thrown is if you fail to use the
    # exact same key names in the custom configuration you pass to the __construct(),
    # thus causing comparison to fail and additional keys to be added
    if (count($this->rules) > count($defaults)) {
      throw new Exception("Malformed rules array (too many entries)");
    }

  }

  /**
   * This is the primary method associated with this class, but all it does it reference the other methods.
   *
   * The idea here is that we start out with the least resource intensive checks first, and work our way
   * down to those which can (depending on length of password to be checked) consume a large amount of
   * system resources. We also break out of the function upon encountering the first error, so as to
   * prevent running anything more than what's absolutely necessary to fail a password.
   *
   * @param string $password This string will replace the original NULL value of $this->password property
   * @param mixed $id Should be an array (if set) of user-specific personally identifiable tokens
   * @return bool Assumes TRUE (meaning NOT a bad password), $errors causes FALSE return
   */
  public function testsPassed($password, $id=null, $break_on_error=true) {

    # Setup additional vars for later
    $this->password = $password;
    $this->rules['identity'] = $id;
    $this->passlen = strlen($this->password);

    # In case you set this to NULL or something other than boolean
    # we revert back to TRUE so as to prevent errors later...
    $this->breakout = (!isset($break_on_error) || !is_bool($break_on_error)) ? true : $break_on_error;

    # Run all tests, but break on first error
    if ($this->breakout) {
      if (!$this->correctLength())  return false;
      if (!$this->correctComp())   return false;
      if (!$this->correctBits())  return false;
      if (!$this->correctDays()) return false;
      if (!$this->noTokens())   return false;
      if ($this->hasMatch())   return false;
      return true;
    }

    # Run all tests and build $errors array
    else {
      $this->correctLength();
      $this->correctComp();
      $this->correctBits();
      $this->correctDays();
      $this->noTokens();
      $this->hasMatch();
      if (!empty($this->errors)) {
        return false;
      }
      return true;
    }
  }

  /**
   * @return array The $errors array (defaults to empty array)
   */
  public function getErrors() {
    return $this->errors;
  }

  /**
   * Checks the length of the password and compares it against the corresponding $rules
   */
  protected function correctLength() {
    if ($this->rules['minlen'] < 10) {
      throw new Exception("Smaug just ate your baby... Don't say I didn't warn you.");
    }
    if ($this->passlen < $this->rules['minlen']) {
      $this->errors[] = sprintf($this->msgs['minlen'], $this->rules['minlen']);
      return false;
    }
    else if ($this->passlen > $this->rules['maxlen']) {
      $this->errors[] = sprintf($this->msgs['maxlen'], $this->rules['maxlen']);
      return false;
    }
    return true;
  }

  /**
   * Checks the composition of the password and compares it against the corresponding $rules[]
   */
  protected function correctComp() {
    if (preg_match_all('/[a-z]/', $this->password, $lower) < $this->rules['lower']) {
      $this->errors[] = sprintf($this->msgs['lower'], $this->rules['lower'], ($this->rules['lower'] > 1) ? 's' : '');
      if ($this->breakout) {
        return false;
      }
    }
    if (preg_match_all('/[A-Z]/', $this->password, $upper) < $this->rules['upper']) {
      $this->errors[] = sprintf($this->msgs['upper'], $this->rules['upper'], ($this->rules['upper'] > 1) ? 's' : '');
      if ($this->breakout) {
        return false;
      }
    }
    if (preg_match_all('/[0-9]/', $this->password, $numbers) < $this->rules['number']) {
      $this->errors[] = sprintf($this->msgs['number'], $this->rules['number'], ($this->rules['number'] > 1) ? 's' : '');
      if ($this->breakout) {
        return false;
      }
    }
    if (preg_match_all('/[\W_]/', $this->password, $special) < $this->rules['special']) {
      $this->errors[] = sprintf($this->msgs['special'], $this->rules['special'], ($this->rules['special'] > 1) ? 's' : '');
      if ($this->breakout) {
        return false;
      }
    }
    $comperrors = array('lower', 'upper', 'number', 'special');
    if (!empty(array_intersect_key($comperrors, $this->errors))) {
      return false;
    }
    return true;
  }

  /**
   * This is a helper method which does half the processing for leet into english
   * Method is useless without its counterpart leetVariations() method
   */
  protected function convert1337() {
    $leet = array(
      '@'=>array('a'), '4'=>array('a'), '7' => array('t'),
      '8'=>array('b'), '3'=>array('e'), '6'=>array('b'),
      '1'=>array('i', 'l'), '!'=>array('i','l','1'),
      '0'=>array('o'), '$'=>array('s'), '5'=>array('s'),
    );
    $map = array();
    $pass_array = str_split(strtolower($this->password));
    foreach($pass_array as $i => $char) {
      $map[$i][] = $char;
      foreach ($leet as $pattern => $replace) {
        if ($char === (string)$pattern) {
          for($j=0,$c=count($replace); $j<$c; $j++) {
            $map[$i][] = $replace[$j];
          }
        }
      }
    }
    $this->passlist = $this->leetVariations($map);
  }

  /**
   * This is another helper method for populating an array of permuted passwords
   * where each possible substitution has been replaced with its plain text counterpart
   */
  protected function leetVariations(&$map, $old = array(), $index = 0) {
    $new = array();
    foreach ($map[$index] as $char) {
      $c = count($old);
      if ($c == 0) {
        $new[] = $char;
      }
      else {
        for ($i=0,$c=count($old); $i<$c; $i++) {
          $new[] = @$old[$i].$char;
        }
      }
    }
    unset($old);
    $r = ($index == count($map)-1) ? $new : $this->leetVariations($map, $new, $index + 1);
    return $r;
  }

  /**
   * Method to check a file or database for the password(s) in question.
   */
  protected function hasMatch() {
    if ($this->rules['lookup']) {
      if (empty($this->passlist)) {
        $this->convert1337();
      }
      if (isset($this->rules['usefile'])) {
        if (!file_exists($this->commons)) {
          throw new Exception('Lookup file not found');
        }
        if (!is_readable($this->commons)) {
          throw new Exception('Lookup file not readable (check permissions)');
        }
        $commons = file($this->commons);
        $matched = array_intersect($commons, $this->passlist);
        if (!empty($matched)) {
          $this->errors[] = $this->msgs['commons'];
          return true;
        }
      }
      else {
        try {
          $db = new PDO(BRUTUS_DBTYPE.':host='.BRUTUS_DBHOST.';dbname='.BRUTUS_DBNAME, BRUTUS_DBUSER, BRUTUS_DBPASS);
          $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
          $matches = 0;
          foreach ($this->passlist as $password) {
            $stmt = $db->prepare("SELECT count(*) FROM `passwords` WHERE `text` = :pass");
            $stmt->bindParam(':pass', $password);
            $stmt->execute();
            if ($stmt->fetchColumn() > 0) {
              $this->errors[] = $this->msgs['commons'];
              return true;
            }
          }
        }
        catch (PDOException $e) {
          throw new Exception($e->getMessage());
        }
        $db = null;
      }
    }
    return false;
  }

  /**
   * Here we check the password against any tokens which may
   * have been passed in the identity array ($this->rules['identity'])
   *
   * @throws Exception if $this->rules['identity'] < 1
   * @throws Exception if $this->rules['identity'] !is_array()
   */
  protected function noTokens() {
    if (isset($this->rules['identity'])) {
      if (!is_array($this->rules['identity'])) {
        throw new Exception("Identity tokens not passed as array");
      }
      else {
        if (empty($this->rules['identity'])) {
          throw new Exception("Identity array is empty");
        }
        else {
          if (empty($this->passlist)) {
            $this->convert1337();
          }
          foreach ($this->rules['identity'] as $token) {
            foreach ($this->passlist as $password) {
              if (preg_match("/$token/i", $password)) {
                $this->errors[] = $this->msgs['identity'];
                return false;
              }
            }
          }
        }
      }
    }
    return true;
  }

  /**
   * We use the original NIST algorithm for calculating password entropy or a
   * modified version of it (depending on the value of $this->rules['diminishing'])
   * to calculate the estimated entropy of the password string.
   */
  public function getNISTbits() {

    $bits = $cnt = 0;
    $char_map = str_split($this->password);
    $char_arr = array_fill(0, 256, 1);

    # Run the original NIST algorithm which
    # has no penalty for repeated characters
    if (!$this->rules['diminishing']) {
      foreach ($char_map as $char) {
        $cnt++;
        if ($cnt == 1) {
          $bits += 4;
        }
        elseif ($cnt > 1 && $cnt <= 8) {
          $bits += 2;
        }
        elseif ($cnt > 8 && $cnt <= 20) {
          $bits += 1.5;
        }
        else {
          $bits += 1;
        }
      }
    }

    # Run the modified NIST algorithm which
    # penalizes you for repeated characters
    # (diminishing returns)
    else {
      for ($cnt = 0; $cnt < $this->passlen; $cnt++) {
        $tmp = ord(substr($this->password, $cnt, 1));

        # Assign 4 bits for the 1st char
        if ($cnt == 1) {
          $bits += 4;
        }

        # Assign 2 bits less the repeat character penalty (if any)
        # for each character between the 2nd and the 8th
        elseif ($cnt > 1 && $cnt <= 8) {
          $bits += $char_arr[$tmp] * 2;
        }

        # Assign 1.5 bits less the repeat character penalty (if any)
        # for each character between the 9th and the 20th
        elseif ($cnt > 8 && $cnt <= 20) {
          $bits += $char_arr[$tmp] * 1.5;
        }

        # Assign 1 bit OR the repeat character penalty (if any)
        # for each character past the 21st
        else {
          $bits += $char_arr[$tmp];
        }

        # Here we penalize the use of repeated characters
        # Each repeat occurence is penalized by cutting the
        # would-be bit value in half, up to the first 3 occurences
        # After which, the bit value is considered to be negated
        # by the repetitiveness and set to 0 for that character
        if ($char_arr[$tmp] >= 0.75) {
          $char_arr[$tmp] *= 0.75;
        }
        elseif ($char_arr[$tmp] >= 0.5625) {
          $char_arr[$tmp] *= 0.375;
        }
        elseif ($char_arr[$tmp] >= 0.421875) {
          $char_arr[$tmp] *= 0.1875;
        }
        else {
          $char_arr[$tmp] *= 0;
        }
      }
    }

    # According to the NIST guidelines, an additional
    # 6 bits can be granted if the password contains
    # a combination of mixed case, numbers, and symbols.
    # We assign each of these a value of 1.5 bits here.
    if (preg_match_all('/[A-Z]/', $this->password, $upper) >= $this->rules['upper']) $bits += 1.5;
    if (preg_match_all('/[a-z]/', $this->password, $lower) >= $this->rules['lower'])  $bits += 1.5;
    if (preg_match_all('/[0-9]/', $this->password, $numbs) >= $this->rules['number'])  $bits += 1.5;
    if (preg_match_all('/[\W_]/', $this->password, $specs) >= $this->rules['special'])  $bits += 1.5;

    # Return result and exit
    return $bits;
  }

  /**
   * Small helper function to actually make the comparison between the result of getNISTbits()
   * and $this->rules['entropy'] in order to allow the previous method to be used independently
   *
   * @return bool Method defaults to TRUE, errors set FALSE return
   */
  protected function correctBits() {
    if ($this->getNISTbits() < $this->rules['entropy']) {
      $this->errors[] = sprintf($this->msgs['entropy'], $this->rules['entropy'], $this->getNISTbits());
      return false;
    }
    return true;
  }


  /**
   * The following method was taken directly from the Mellt class by ravisorg (https://github.com/ravisorg/Mellt)
   *
   * @author ravisorg
   * Copyright (c) 2012, ravisorg
   * All rights reserved.
   *
   * @license BSD
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions are met:
   *     * Redistributions of source code must retain the above copyright
   *       notice, this list of conditions and the following disclaimer.
   *     * Redistributions in binary form must reproduce the above copyright
   *       notice, this list of conditions and the following disclaimer in the
   *       documentation and/or other materials provided with the distribution.
   *     * Neither the name of the Travis Richardson nor the names of its
   *       contributors may be used to endorse or promote products derived
   *       from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   * DISCLAIMED. IN NO EVENT SHALL TRAVIS RICHARDSON BE LIABLE FOR ANY
   * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
  public function simBrute() {
    $base = ''; $baseKey = NULL;
    for ($t = 0; $t < $this->passlen; $t++) {
      $char = $this->password[$t];
      $foundChar = false;
      foreach ($this->charSets as $characterSetKey=>$characterSet) {
        if ($baseKey<=$characterSetKey && strpos($characterSet,$char)!==false) {
          $baseKey = $characterSetKey;
          $base = $characterSet;
          $foundChar = true;
          break;
        }
      }
      # If the character we were looking for wasn't anywhere in any of the
      # character sets, assign the largest (last) character set as default.
      if (!$foundChar) {
        $base = end($this->charSets);
        break;
      }
    }
    unset($baseKey, $foundChar);

    # Starting at the first character, figure out it's position in the character set
    # and how many attempts will take to get there. For example, say your password
    # was an integer (a bank card PIN number for example):
    # 0 (or 0000 if you prefer) would be the very first password they attempted by the attacker.
    # 9999 would be the last password they attempted (assuming 4 characters).
    # Thus a password/PIN of 6529 would take 6529 attempts until the attacker found
    # the proper combination. The same logic words for alphanumeric passwords, just
    # with a larger number of possibilities for each position in the password. The
    # key thing to note is the attacker doesn't need to test the entire range (every
    # possible combination of all characters) they just need to get to the point in
    # the list of possibilities that is your password. They can (in this example)
    # ignore anything between 6530 and 9999. Using this logic, 'aaa' would be a worse
    # password than 'zzz', because the attacker would encounter 'aaa' first.
    $attempts = 0;
    $charactersInBase = strlen($base);
    for ($position = 0; $position < $this->passlen; $position++) {
      # We power up to the reverse position in the string. For example, if we're trying
      # to hack the 4 character PING code in the example above:
      # First number * (number of characters possible in the charset ^ length of password)
      # ie: 6 * (10^4) = 6000
      # then add that same equation for the second number:
      # 5 * (10^3) = 500
      # then the third numbers
      # 2 * (10^2) = 20
      # and add on the last number
      # 9
      # Totals: 6000 + 500 + 20 + 9 = 6529 attempts before we encounter the correct password.
      $powerOf = $this->passlen - $position - 1;
      # Character position within the base set. We add one on because strpos is base
      # 0, we want base 1.
      $charAtPosition = strpos($base,$this->password[$position])+1;
      # If we're at the last character, simply add it's position in the character set
      # this would be the "9" in the pin code example above.
      if ($powerOf==0) {
        $attempts = bcadd($attempts,$charAtPosition);
      }
      # Otherwise we need to iterate through all the other characters positions to
      # get here. For example, to find the 5 in 25 we can't just guess 2 and then 5
      # (even though Hollywood seems to insist this is possible), we need to try 0,1,
      # 2,3...15,16,17...23,24,25 (got it).
      else {
        # This means we have to try every combination of values up to this point for
        # all previous characters. Which means we need to iterate through the entire
        # character set, X times, where X is our position -1. Then we need to multiply
        # that by this character's position.

        # Multiplier is the (10^4) or (10^3), etc in the pin code example above.
        $multiplier = bcpow($charactersInBase,$powerOf);
        # New attempts is the number of attempts we're adding for this position.
        $newAttempts = bcmul($charAtPosition,$multiplier);
        # Add that on to our existing number of attempts.
        $attempts = bcadd($attempts,$newAttempts);
      }
    }

    # We can (worst case) try one billion passwords per second. Calculate how many days
    # it will take us to get to the password using only brute force attempts.
    $perDay = bcmul($this->hashpsec,60*60*24);

    # This allows us to calculate a number of days to crack. We use days because anything
    # that can be cracked in less than a day is basically useless, so there's no point in
    # having a smaller granularity (hours for example).
    $days = bcdiv($attempts,$perDay);

    # If it's going to take more than a billion days to crack, just return a billion. This
    # helps when code outside this function isn't using bcmath. Besides, if the password
    # can survive 2.7 million years it's probably ok.
    if (bccomp($days,1000000000)==1) {
      $days = 1000000000;
    }

    # Return result and exit
    return $days;
  }

  /**
   * Small helper function to actually make the comparison between the result of simBrute()
   * and $this->rules['brute'] in order to allow the previous method to be used independently
   *
   * @return bool Method defaults to TRUE, errors set FALSE return
   */
  protected function correctDays() {
    if ($this->simBrute() < $this->rules['brute']) {
      $this->errors[] = sprintf($this->msgs['brute'], $this->rules['brute'], $this->simBrute());
      return false;
    }
    return true;
  }
}