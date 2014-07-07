<?php

require_once('Brutus.class.php');

if (!isset($_POST['password'])) {
  $password = 'L337 H4x0R';
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
  'min'=>10,
  'max'=>50,
  'lookup'=>true,
  'lower'=>2,
  'upper'=>2,
  'numeric'=>1,
  'special'=>1,
  'identity'=>array(),
  'entropy'=>30,
  'brute'=>60
);

$brutus = new Brutus($args);

if ($brutus->badPass($password) && count($brutus->showErrors()) > 0) {
  echo '<p>';
  foreach($brutus->showErrors() as $error) {
    echo $error.'<br>';
  }
  echo '</p>';
}
else {
  echo '<p>You have a strong password!</p>';
}

?>

<form method="post" action="">
  <input type="text" value="<?php echo $password; ?>" id="password" name="password">
  <input type="submit" value="Check Password">
</form>