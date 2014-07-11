<img src="https://raw.githubusercontent.com/UberNerdBoy/Brutus/master/assets/brutus.png" alt="Brutus">

A simple, yet comprehensive password grading and validation class which utilizes tried and tested methods for quantifying a password's strength as well as enforcing a security policy that conforms to a definable set of rules.

Includes a dictionary file of the 10k most common passwords (kudos Mike Burnett), as well as an alphabetized list of common dictionary terms which can be used for testing the password's projected strength against dictionary attacks. Also converts leetspeak to its basic english counterparts, thus reducing the keyspace needed to bruteforce a password. However, when using this feature in conjunction with the dictionary lookup method, the performance impact is severe.

Usage
-----
```php
$brutus = new Brutus();

/**
 * The password checking method assumes first
 * that the password is NOT "bad", therefore
 * returning false until the errors array is
 * greater than zero, thus causing the method
 * to return "true", indicating the password
 * is, indeed, a "bad" password.
 */
if($brutus->badPass($password)) {
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
- [ ] find more efficient solution to leetspeak dictionary lookups
- [ ] simplify the string translation method
- [ ] MOAR PERFORMANCE TWEAKING!!!
