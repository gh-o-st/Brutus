<?php

/** 
 *
 * The basic configuration settings for the Brutus password strength verification system.
 *
 * This file includes configuration settings for your MySQL database and intended use.
 * Read the comments for instructions regarding possible values, or for more
 * detailed information, please see the readme file included with this project.
 * All MySQL settings can be obtained from your web hosting provider if needed.
 *
 * @author Josh Jones
 * @version 1.0
 * @license GPL3
 *
 * Yes, this was shamelessly stolen from WordPress.
 * No, I don't see anything wrong with that.
 * To avoid collisions, the constants have been prepended with MSVS
 */



/**
 * @var string BRUTUS_DB the name of the database you want the system to write to
 * @var string BRUTUS_HOST the hostname used by MySQL (most hosting providers use "localhost")
 * @var string BRUTUS_USER name of the user with priveleges and access to the database
 * @var string BRUTUS_PASS password for the user mentioned above
 * @var string BRUTUS_TABLE the table that contains the dictionary terms
 * @var string BRUTUS_CHARSET character set used when creating new tables
 * @var string BRUTUS_COLLATE the database collate type (don't change if in doubt)
 */
define('BRUTUS_NAME', 'dictionary');
define('BRUTUS_HOST', 'localhost');
define('BRUTUS_USER', 'root');
define('BRUTUS_PASS', '');
define('BRUTUS_TABLE', 'words');
define('BRUTUS_CHARSET', 'utf8');
define('BRUTUS_COLLATE', 'utf8_unicode_ci');











try {
  $db = new PDO("mysql:host=".BRUTUS_HOST.";dbname=".BRUTUS_NAME, BRUTUS_USER, BRUTUS_PASS);
}
catch (PDOException $x) {
  echo $x->getMessage();
}




require_once('Brutus.class.php');

if (!isset($_POST['password'])) {
  $password = 'Chr!$70ph3r_P@$$w0Rd';
}
else {
  $password = htmlspecialchars($_POST['password']);
}

// Identity tokens are easily captureable
// from previously filled in form fields
// Things like the user's chosen username,
// their birth year, first and last name, etc.
// Each would be passed into the "identity" array
$args = array(
  'minlen'=>10,
  'maxlen'=>50,
  'lookup'=>false,
  'lower'=>2,
  'upper'=>2,
  'numeric'=>1,
  'special'=>1,
  'entropy'=>30,
  'brute'=>60
);
$id = array(
  'chris',
  'christopher',
  'columbus',
  '1492',
  'asiaorbust'
);



try {
  $brutus = new Brutus($args);
  if ($brutus->badPass($password, $id) && count($brutus->showErrors()) > 0) {
    echo '<p>';
    foreach($brutus->showErrors() as $error) {
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


?>

<form method="post" action="">
  <input type="text" value="<?php echo $password; ?>" id="password" name="password">
  <input type="submit" value="Check Password">
</form>