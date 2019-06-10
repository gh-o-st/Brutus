<img src="https://raw.githubusercontent.com/UberNerdBoy/Brutus/master/assets/brutus.png" alt="Brutus">

A simple, yet comprehensive password grading and validation class which utilizes tried and tested methods for quantifying a password's strength as well as enforcing a security policy that conforms to a definable set of rules.

Includes a dictionary file of the 10k most common passwords (kudos Mark Burnett), as well as an alphabetized list of common dictionary terms which can be used for testing the password's projected strength against dictionary attacks. Also converts leetspeak to its basic english counterparts, thus reducing the keyspace needed to bruteforce a password. However, when using this feature in conjunction with the dictionary lookup method, the performance impact is severe.


Default Args
-----
The entire array below is passed to the `__construct()` method, so if the defaults are fine with you then there's no reason to pass anything in the instansiation of the class. However, if you wish to pass your own custom values, you must use the same key names in the array for the class methods to function properly.
```php
$args = array(
  'brute' => 60, # How long the password should survive a continued brute force attack
  'lower' => 2, # The number of lowercase letters required
  'upper' => 2, # The number of uppercase letters required
  'number' => 1, # The number of numeric characters required
  'minlen' => 10, # The minimum length of the password (less than 10 is discouraged)
  'maxlen' => 50, # The maximum length of the password
  'lookup' => true, # Whether or not to check the password against the dictionar(y/ies)
  'special' => 1, # The number of special characters required in the password
  'entropy' => 30, # The number of entropic bits the password must have
  'usefile' => null, # Whether to use a physical file instead of a database
  'diminishing' => true, # Whether to penalize a password for repetitive characters
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

Advanced Usage
-----
One feature I think is often overlooked when grading a password is that of identification tokens. At the very least, most authentication methods require either a username or an email address and a password. So why not use that second piece of information in the grading of the password's strength? This can be further improved upon if the user is registering for a site or service using a signup form which allows them to fill out multiple pieces of personal information (such as first name, last name, DOB, age, sex, etc). 

To be clear, none of this information is stored by the class or any piece of its functionality, but could be passed to it as an array to use when verifying the password the user decides to use when creating their account. I think it's a missed opportunity, as someone bent on gaining access to a particular account wouldn't have picked that account by random chance. They will have done some research on the individual who owns it and may likely have similar information to aid in their attack.

```php
/**
 * So let's pretend Christopher Columbus signed up for our service
 * using a form which we're able to grab the values from to pass
 * to the Brutus class while he registers his username and password
 */
$id = array(
  'christopher',
  'columbus',
  '1451'
);

// And here is the password he chose
$password = 'ChR!$_1451';

try {
  $brutus = new Brutus($args);
  if (!$brutus->testsPassed($password, $id, false) && !empty($brutus->getErrors())) {
    echo '<p>';
    foreach($brutus->getErrors() as $error) {
      echo $error.'<br>';
    }
    echo '</p>';
  }
  else {
    echo '<p>You have a strong password!</p>';
  }
}
catch (Exception $e) {
  echo '<p>Caught Exception: '.$e->getMessage().'</p>';
}
```

With the combination of identification tokens and the ability to convert *1337* into plain english, poor Christopher's password would be rejected as too weak. Sorry bro... Try again.


Todo
-----
- [ ] Performance Tweaks and Optimization
- [ ] Update common passwords list
- [ ] Include (optional) more extensive password list
- [ ] Convert to WP plugin?
- [ ] Modularize functionality into multiple classes?
