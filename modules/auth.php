<?php
/**
 * This file is a part of MyWebSQL package
 *
 * @file:      modules/auth.php
 * @author     Samnan ur Rehman
 * @copyright  (c) 2008-2012 Samnan ur Rehman
 * @web        http://mywebsql.net
 * @license    http://mywebsql.net/license
 */
	class MyWebSQL_Authentication {
		private $error;
		private $username;
		private $password;
		private $db;
		private $server;
		private $custom_auth;

		public function authenticate() {

			include_once(BASE_PATH . '/lib/db/manager.php');
			$this->db = new DbManager();
			$this->error = '';
			$this->username = '';
			$this->password = '';
			$this->server = array();
			$this->custom_auth = null;

			// change of auth type at runtime invalidates session
			if (Session::get('auth', 'type') != AUTH_TYPE)
				Session::del('auth', 'valid');

			if (Session::get('auth', 'valid'))
				return $this->setParameters();

			if (AUTH_TYPE == 'NONE')
				$this->getAuthNone();
			else if (AUTH_TYPE == 'BASIC')
				$this->getAuthBasic();
			else if (AUTH_TYPE == 'SPROXY')
				$this->getAuthSproxy();
			else if (AUTH_TYPE == 'LOGIN') {
				if (secureLoginPage())
					$this->getAuthSecureLogin();
				else
					$this->getAuthLogin();
			} else if (AUTH_TYPE == 'CUSTOM') {
				require_once(BASE_PATH . '/lib/auth/custom.php');
				$this->custom_auth = new MyWebSQL_Auth_Custom();
				$this->getAuthCustom();
			}
			
			if (Session::get('auth', 'valid'))
				return $this->setParameters();

			return false;
		}

		public function getUserName() {
			return $this->username;
		}

		public function getUserPassword() {
			return $this->password;
		}

		public function getServerInfo() {
			return $this->server[1];
		}
		
		public function getCustomServer() {
			return v($_POST['server_name']);
		}
		
		public function getCustomServerType() {
			return v($_POST['server_type']);
		}
		
		public function getError() {
			return $this->error;
		}

		private function setError($str) {
			$this->error = $str;
			return false;
		}

		private function setParameters() {
			switch(AUTH_TYPE) {
				case 'NONE':
					$this->server = $this->getDefaultServer();
					$this->username = AUTH_LOGIN;
					$this->password = AUTH_PASSWORD;
					break;
				case 'BASIC':
					$this->server = $this->getDefaultServer();
				case 'SPROXY':
					$this->server = $this->getDefaultServer();
				case 'LOGIN':
					$server_name = Session::get('auth', 'server_name', true);
					$this->server = $this->getServer($server_name);
					$this->username = Session::get('auth', 'user', true);
					$this->password = Session::get('auth', 'pwd', true);
					break;
				case 'CUSTOM':
					require_once(BASE_PATH . '/lib/auth/custom.php');
					$this->custom_auth = new MyWebSQL_Auth_Custom();
					$param = $this->custom_auth->getParameters();
					$this->username = v($param['username']);
					$this->password = v($param['password']);
					break;
			}

			Session::set('auth', 'type', AUTH_TYPE);
			// set the language
			include(CONFIG_PATH . '/lang.php');
			if (isset($_REQUEST["lang"]) && array_key_exists($_REQUEST["lang"], $_LANGUAGES) && file_exists(BASE_PATH . '/lang/'.$_REQUEST["lang"].'.php')) {
				$_lang = $_REQUEST["lang"];
				setcookie("lang", $_REQUEST["lang"], time()+(COOKIE_LIFETIME*60*60), EXTERNAL_PATH);
			}

			return true;
		}

		private function getAuthNone() {
			$server = $this->getDefaultServer();
			Session::set('auth', 'valid', true);
			Session::set('auth', 'server_name', $server[0], true);
			Session::set('auth', 'host', $server[1]['host'], true);
			Session::set('auth', 'user', AUTH_LOGIN, true);
			Session::set('auth', 'pwd', AUTH_PASSWORD, true);
			Session::set('db', 'driver', $server[1]['driver']);
			header('Location: '.EXTERNAL_PATH);
			return true;	
		}

		private function getAuthBasic() {
			$server = $this->getDefaultServer();
			if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
				if ($this->db->connect($server[1],$_SERVER['PHP_AUTH_USER'],$_SERVER['PHP_AUTH_PW']))	{
					Session::set('auth', 'valid', true);
					Session::set('auth', 'server_name', $server[0], true);
					Session::set('auth', 'host', $server[1]['host'], true);
					Session::set('auth', 'user', $_SERVER['PHP_AUTH_USER'], true);
					Session::set('auth', 'pwd', $_SERVER['PHP_AUTH_PW'], true);
					Session::set('db', 'driver', $server[1]['driver']);
					$this->db->disconnect();
					return true;
				} else
					$this->setError( $this->db->getError() );
			}

			header('WWW-Authenticate: Basic realm="MyWebSQL"');
			header($_SERVER['SERVER_PROTOCOL'].' 401 Unauthorized');
			echo __('Invalid Credentials supplied');

			return false;
		}

		private function getAuthSproxy() {
			if (!isset($_SERVER['HTTP_FROM'])) {
				die('Not authorized');
			}
			list ($username, $host) = explode('@', $_SERVER['HTTP_FROM'], 2);
			log_message("auth: sproxy: from $username@$host");
			$server = $this->getDefaultServer();
			if (strstr($server[1]['driver'], 'mysql')) {
				// MySQL hardcoded limit:
				if (strlen($username) > 16)
					$username = substr($username, 0, 16);
			}
			log_message("auth: sproxy: normal username $username");
			Session::set('auth', 'server_name', $server[0], true);
			Session::set('auth', 'host', $server[1]['host'], true);
			Session::set('auth', 'user', $username, true);
			Session::set('auth', 'pwd', '', true);
			Session::set('db', 'driver', $server[1]['driver']);
			Session::set('auth', 'valid', true);
			return true;
		}

		private function getAuthLogin() {
			if (isset($_POST['auth_user']) && isset($_POST['auth_pwd'])) {
				$server = $this->getServer( v($_POST['server']) );
				$this->username = $_POST['auth_user'];
				if ($this->db->connect($server[1], $_POST['auth_user'], $_POST['auth_pwd']))	{
					Session::set('auth', 'valid', true);
					Session::set('auth', 'server_name', $server[0], true);
					Session::set('auth', 'host', $server[1]['host'], true);
					Session::set('auth', 'user', $_POST['auth_user'], true);
					Session::set('auth', 'pwd', $_POST['auth_pwd'], true);
					Session::set('db', 'driver', $server[1]['driver']);
					$this->db->disconnect();
					header('Location: '.EXTERNAL_PATH);
					return true;
				} else
					$this->setError( $this->db->getError() );
			}

			return false;
		}

		private function getAuthSecureLogin() {
			if (isset($_POST['mywebsql_auth'])) {
				$enc_lib = BASE_PATH . ((extension_loaded('openssl') && extension_loaded('gmp'))
					? "/lib/external/jcryption.php"
					: "/lib/external/jcryption-legacy.php");
				require_once( $enc_lib );
				$jCryption = new jCryption();
				$d = Session::get('auth_enc', 'd');
				$n = Session::get('auth_enc', 'n');
				if ( !isset($d['int']) || !isset($n['int']) )
					return $this->setError('Invalid Credentials');
				$decoded = $jCryption->decrypt($_POST['mywebsql_auth'], $d['int'], $n['int']);
				if (!$decoded)
					return $this->setError('Invalid Credentials');
				parse_str($decoded, $info);
				
				// custom server variables are included in the decoded array
				if ( isset($info['server_name']) )
					$_POST['server_name'] = $info['server_name'];
				if ( isset($info['server_type']) )
					$_POST['server_type'] = $info['server_type'];
				
				$server = $this->getServer( v($info['server']) );
				$this->username = v($info['auth_user']);
				$this->password = v($info['auth_pwd']);
				
				// extract encrypted variables for splash screen
				$_REQUEST['server'] = v($info['server']);
				$_REQUEST['lang'] = v($info['lang']);
				
				if ($this->db->connect($server[1], $this->username, $this->password)) {
					Session::del('auth_enc');
					Session::set('auth', 'valid', true);
					Session::set('auth', 'server_name', $server[0], true);
					Session::set('auth', 'host', $server[1]['host'], true);
					Session::set('auth', 'user', $this->username, true);
					Session::set('auth', 'pwd', $this->password, true);
					Session::set('db', 'driver', $server[1]['driver']);
					$this->db->disconnect();
					header('Location: '.EXTERNAL_PATH);
					return true;
				} else
					$this->setError( $this->db->getError() );
			}

			return false;
		}

		private function getAuthCustom() {
			$server = $this->getDefaultServer();
			$username = $password = '';

			if (secureLoginPage() && isset($_POST['mywebsql_auth']) ) {
				$enc_lib = BASE_PATH . ((extension_loaded('openssl') && extension_loaded('gmp')) ? "/lib/external/jcryption.php"
				: "/lib/external/jcryption-legacy.php");
				require_once( $enc_lib );
				$jCryption = new jCryption();
				$d = Session::get('auth_enc', 'd');
				$n = Session::get('auth_enc', 'n');
				if ( !isset($d['int']) || !isset($n['int']) )
					return $this->setError('Invalid Credentials');
				$decoded = $jCryption->decrypt($_POST['mywebsql_auth'], $d['int'], $n['int']);
				if (!$decoded)
					return $this->setError('Invalid Credentials');
				parse_str($decoded, $info);
				$server = $this->getServer( v($info['server']) );
				$username = v($info['auth_user']);
				$password = v($info['auth_pwd']);
			} else if (isset($_POST['auth_user']) && isset($_POST['auth_pwd'])) {
				$server = $this->getServer(v($_POST['server']));
				$username = v($_POST['auth_user']);
				$password = v($_POST['auth_pwd']);
			}
			
			return $this->custom_auth->authenticate($username, $password, $server);
			
			return false;
		}
		
		private function getServer( $selection ) {
			$serverList = getServerList();
			
			// if only one server is defined, it is used
			if( count($serverList) == 1) {
				$server = key($serverList);
				$host = current($serverList);
				return array($server, $host);
			}
			
			// return a server based on user's selection
			foreach($serverList as $server => $host) {
				if ($server == $selection)
					return array($server, $host);
			}
			
			// check if a custom server is selected
			if ( $selection == '' && ALLOW_CUSTOM_SERVERS ) {
				$address = v($_POST['server_name']);
				$type = v($_POST['server_type']);
				$allowed_types = explode(',', ALLOW_CUSTOM_SERVER_TYPES);
				$driver = in_array($type, $allowed_types) ? $type : '';
				if ($address && $driver) {
					// found a valid custom server definition, return it
					$server = array(__('Custom Server'), array('host' => $address, 'driver' => $driver));
					return $server;
				}
			}
		}
		
		private function getDefaultServer() {
			$serverList = getServerList();
			$server = key($serverList);
			$host = current($serverList);
			return array($server, $host);
		}
	}
?>
