<img src="https://raw.githubusercontent.com/UberNerdBoy/Brutus/master/assets/brutus.png" alt="Brutus">

A simple, yet comprehensive password grading and validation class which utilizes tried and tested methods for quantifying a password's strength as well as enforcing a security policy that conforms to a definable set of rules.

Includes a dictionary file of the 10k most common passwords (kudos Mark Burnett), as well as an alphabetized list of common dictionary terms which can be used for testing the password's projected strength against dictionary attacks. Also converts leetspeak to its basic english counterparts, thus reducing the keyspace needed to bruteforce a password. However, when using this feature in conjunction with the dictionary lookup method, the performance impact is severe.


Default Args
-----
Everything in this array is set as seen below in the `__construct()` method. So if the defaults are fine with you, there's no reason to pass anything in the instansiation of the class. However, if you wish to pass your own custom values, you must use the same key names in the array for the class methods to function properly.
```php
$args = array(
  'brute' => 60,
  'lower' => 2,
  'upper' => 2,
  'number' => 1,
  'minlen' => 10,
  'maxlen' => 50,
  'lookup' => true,
  'special' => 1,
  'entropy' => 30,
  'usefile' => null,
  'dataset' => 'commons',
  'diminishing' => true,
);
```

Basic Usage
-----
```php

$brutus = new Brutus($args);

/**
 * The password checking method assumes first
 * that the password is NOT "bad", therefore
 * returning false until the errors array is
 * greater than zero, thus causing the method
 * to return "true", indicating the password
 * is, indeed, a "bad" password.
 */
if($brutus->badPass($password, $id)) {
  foreach($brutus->showErrors() as $error) {
    echo $error.'<br>';
  }
}
```

Todo
-----
- [x] modularize the functionality more efficiently
- [x] original NIST entropy calculation + modified version
- [x] id tokens passed directly to method rather than constructor
- [x] 2 methods for dictionary lookup; file or database
- [x] PHPDoc commenting throughout
- [ ] simplify the string translation method
- [ ] MOAR PERFORMANCE TWEAKING!!!
