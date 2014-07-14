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
 */



/**
 * @var string BRUTUS_DBTYPE the type of database you're working with
 * @var string BRUTUS_DBNAME the name of the database you want the system to write to
 * @var string BRUTUS_DBHOST the hostname used by MySQL (most hosting providers use "localhost")
 * @var string BRUTUS_DBUSER name of the user with priveleges and access to the database
 * @var string BRUTUS_DBPASS password for the user mentioned above
 * @var string BRUTUS_CHARSET character set used when creating new tables
 * @var string BRUTUS_COLLATE the database collate type (don't change if in doubt)
 */
define('BRUTUS_DBTYPE', 'mysql');
define('BRUTUS_DBNAME', 'dictionary');
define('BRUTUS_DBHOST', 'localhost');
define('BRUTUS_DBUSER', 'root');
define('BRUTUS_DBPASS', '');
define('BRUTUS_CHARSET', 'utf8');
define('BRUTUS_COLLATE', 'utf8_unicode_ci');