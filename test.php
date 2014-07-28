<?php


require_once('config.php');
require_once('Brutus.class.php');

if (!isset($_POST['password'])) {
  $password = 'Chr!$70ph3r_P@$$w0Rd';
}
else {
  $password = htmlspecialchars($_POST['password']);
}


$args = array(
  'minlen'=>10,
  'maxlen'=>50,
  'lookup'=>true,
  'lower'=>2,
  'upper'=>2,
  'numeric'=>1,
  'special'=>1,
  'entropy'=>30,
  'brute'=>60,
  'dataset'=>'both'
);

// Identity tokens are easily captureable
// from previously filled in form fields
// Things like the user's chosen username,
// their birth year, first and last name, etc.
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


$bits = $cnt = 0;
$char_map = str_split($this->password);
$char_arr = array_fill(0, 256, 1);
for ($cnt = 0; $cnt < strlen($password); $cnt++) {
  $tmp = ord(substr($password, $cnt, 1));

  # Assign 4 bits for the 1st char
  if ($cnt == 1) {
    $bits += 4;
  }

  # Assign 
  elseif ($cnt > 1 && $cnt <= 8) {
    $bits += $char_arr[$tmp] * 2;
    echo '$char_arr[$tmp] * 2 = '.$char_arr[$tmp] * 2.'<br>';
  }
  elseif ($cnt > 8 && $cnt <= 20) {
    $bits += $char_arr[$tmp] * 1.5;
    echo '$char_arr[$tmp] * 1.5 = '.$char_arr[$tmp] * 1.5.'<br>';
  }
  else {
    $bits += $char_arr[$tmp];
    echo '$char_arr[$tmp] = '.$char_arr[$tmp].'<br>';
  }
  $char_arr[$tmp] *= 0.75;
  echo '$char_arr[$tmp] * 0.75 = '.$char_arr[$tmp] *= 0.75.'<br>';
}

?>

<form method="post" action="">
  <input type="text" value="<?php echo $password; ?>" id="password" name="password">
  <input type="submit" value="Check Password">
</form>