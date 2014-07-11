Brutus
======

A simple, yet comprehensive password grading and validation class which utilizes tried and tested methods for quantifying a password's strength as well as enforcing a security policy that conforms to a definable set of rules.

Usage
-----
```php
$brutus = new Brutus();

if($brutus->badPass($password)) {
  foreach($brutus->showErrors() as $error) {
    echo $error.'<br>';
  }
}
```