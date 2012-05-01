<?php
class securityTools
{
	public
		$adminUsername = '',
		$dbPrefix      = '',
		$filesIssues   = 0,
		$messages      = array(),
		$pluginPath    = '',
		$updateCore    = FALSE,
		$xssRegex      = '(<script|<iframe|<object|<embed|XMLHttpRequest\(|ActiveXObject\(|onabort\s*=|onblur\s*=|onchange\s*=|onclick\s*=|ondblclick\s*=|ondragdrop\s*=|onerror\s*=|onfocus\s*=|onkeydown\s*=|onkeypress\s*=|onkeyup\s*=|onload\s*=|onmousedown\s*=|onmousemove\s*=|onmouseout\s*=|onmouseover\s*=|onmouseup\s*=|onmove\s*=|onreset\s*=|onresize\s*=|onselect\s*=|onsubmit\s*=|onunload\s*=|("|\')javascript:)'
		;

	function init()
	{
		if ( $_SERVER['HTTPS'] != 'on' && get_option('st_force_ssl') && preg_match('/\/wp\-admin|\/wp\-login\.php/', $_SERVER['REQUEST_URI']) )
		{
			header('Location: https://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI']);

			exit;
		}

		wp_enqueue_script('jquery');
		wp_enqueue_script('jquery-ui-core');
		wp_enqueue_script('jquery-ui-tabs');
		
		// Download new wp-config.php
		if ( !empty($_GET['st_genconf_prefix']) )
		{
			header('Content-type: application/x-php');
			header('Content-Disposition: attachment; filename="wp-config.php"');
			header('Cache-Control: no-cache, must-revalidate');
			header('Expires: Sat, 26 Jul 1997 05:00:00 GMT');

			$contents = file_get_contents(str_replace('\\', '/', ABSPATH) . '/wp-config.php');

			echo preg_replace('/\$table_prefix[^;]+;/', '$table_prefix = \'' . addslashes($_GET['st_genconf_prefix']) . '\';', $contents);

			exit;
		}

		if ( !empty($_POST['st_action']) )
		{
			$this->process_form();
		}

		// Log POST requests
		if ( !empty($_POST) )
		{
			global $wpdb;

			$r = $wpdb->get_var('SHOW TABLES LIKE "' . $wpdb->prefix . 'st_log_post"');

			if ( $r )
			{
				$post = $_POST;

				foreach ( array('pwd', 'pass1', 'pass2') as $k )
				{
					if ( isset($post[$k]) )
					{
						$post[$k] = '*****';
					}
				}

				$sql = '
					INSERT INTO `' . $wpdb->prefix . 'st_log_post` (
						`datetime`,
						`data`,
						`ip_addr`,
						`agent`,
						`url`
						)
					VALUES (
						NOW(),
						"' . $wpdb->escape(serialize($post)) . '",
						"' . $wpdb->escape($_SERVER['REMOTE_ADDR']) . '",
						"' . ( isset($_SERVER['HTTP_USER_AGENT']) ? $wpdb->escape($_SERVER['HTTP_USER_AGENT']) : '' ) . '",
						"' . $wpdb->escape($_SERVER['REQUEST_URI']) . '"
						)
					;';
				
				$wpdb->query($sql);
			}
		}

		// Messages
		if ( !session_id() )
		{
			session_start();
		}
		
		if ( !empty($this->messages) )
		{
			$_SESSION['st_messages'] = serialize($this->messages);

			header('Location: ' . $_SERVER['REQUEST_URI']);

			exit;
		}

		if ( isset($_SESSION['st_messages']) )
		{
			$this->messages = unserialize($_SESSION['st_messages']);
			
			unset($_SESSION['st_messages']);
		}
	}

	function install()
	{
		global $wpdb;

		$sql = '';

		$r = $wpdb->get_var('SHOW TABLES LIKE "' . $table_prefix . 'st_log_post"');

		if ( !$r )
		{
			$sql .= '
				CREATE TABLE `' . $wpdb->prefix . 'st_log_post` (
					`id`       INT(10) UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
					`datetime` DATETIME         NOT NULL,
					`data`     TEXT             NOT NULL,
					`ip_addr`  VARCHAR(255)     NOT NULL,
					`agent`    VARCHAR(255)     NOT NULL,
					`url`      VARCHAR(255)     NOT NULL,
					INDEX (`datetime`)
				)
				;';
		}

		$r = $wpdb->get_var('SHOW TABLES LIKE "' . $table_prefix . 'st_log_failed_logins"');

		if ( !$r )
		{
			$sql .= '
				CREATE TABLE `' . $wpdb->prefix . 'st_log_failed_logins` (
					`id`       INT(10) UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
					`datetime` DATETIME         NOT NULL,
					`username` VARCHAR(255)     NOT NULL,
					`ip_addr`  VARCHAR(255)     NOT NULL,
					`agent`    VARCHAR(255)     NOT NULL,
					INDEX (`datetime`)
				)
				;';
		}

		if ( $sql )
		{
			require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

			dbDelta($sql);
		}

		// SSL
		add_option('st_force_ssl', 0);
	}

	function head()
	{
		echo '<link type="text/css" rel="stylesheet" href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.10/themes/base/jquery-ui.css"/>' . "\n";
	}

	private function process_form()
	{
		global $wpdb;
		
		switch ( $_POST['st_action'] )
		{
			case 'db prefix':
				$newPrefix = substr(sha1(rand()), rand(0, 35), 5) . '_';

				$r = $wpdb->get_results('SHOW TABLES LIKE "' . $newPrefix . '%";', ARRAY_N);

				if ( $r )
				{
					$this->messages[] = '<strong>ERROR:</strong> Table prefix "' . $newPrefix . '" is already in use, please try again.';
				}
				else
				{				
					$tables = $wpdb->get_results('SHOW TABLES LIKE "' . $wpdb->prefix . '%"', ARRAY_N);
					
					if ( $tables )
					{
						$tablesCopied = array();
						
						foreach ( $tables as $table )
						{
							$table = substr($table[0], strlen($wpdb->prefix), strlen($table[0]));
							
							$sql = '
								CREATE TABLE `' . $newPrefix . $table . '`
								LIKE `' . $wpdb->prefix . $table . '`
								;';
							
							$r = $wpdb->query($sql);
							
							if ( $r === FALSE )
							{
								$this->messages[] = '<strong>ERROR:</strong> Could not create table "' . $newPrefix . $table . '".';
							}
							else
							{							
								$sql = '
									INSERT INTO `' . $newPrefix . $table . '`
									SELECT
										*
									FROM `' . $wpdb->prefix . $table . '`
									;';
								
								$r = $wpdb->query($sql);
								
								if ( $r === FALSE )
								{
									$this->messages[] = '<strong>ERROR:</strong> Could not copy table "' . $wpdb->prefix . $table . '" to "' . $newPrefix . $table . '".';
								}
								else
								{
									$tablesCopied[] = $table;
								}
							}
						}
						
						if ( count($tablesCopied) == count($tables) )
						{
							$sql = '
								UPDATE `' . $newPrefix . 'options` SET
									`option_name` = "' . $newPrefix . 'user_roles"
								WHERE
									`option_name` = "' . $wpdb->prefix . 'user_roles"
								LIMIT 1
								;';
							
							$r = $wpdb->query($sql);
							
							if ( $r === FALSE )
							{
								$this->messages[] = '<strong>ERROR:</strong> Could not update prefix refences in "' . $newPrefix . 'options" table.';
							}
							else
							{
								$fields = array(
									'user_level',
									'capabilities',
									'autosave_draft_ids'
									);

								foreach ( $fields as $field )
								{
									$sql = '
										UPDATE `' . $newPrefix . 'usermeta` SET
											`meta_key` = "' . $newPrefix . 'capabilities"
										WHERE
											`meta_key` = "' . $wpdb->prefix . 'capabilities"
										LIMIT 1
										;';

									$r = $wpdb->query($sql);

									if ( $r === FALSE )
									{
										$this->messages[] = '<strong>ERROR:</strong> Could not update prefix refences in "' . $newPrefix . 'usermeta" table.';
									}
								}

								if ( !$this->messages )
								{
									$this->messages[] = 'All tables have been copied successfully.';
									$this->messages[] = '<strong>IMPORTANT:</strong> You will need to manually change the value of "$table_prefix" to "' . $newPrefix . '" in the file "wp-config.php" or replace the file completely: <a href="' . $_SERVER['REQUEST_URI'] . '&st_genconf_prefix=' . $newPrefix . '">download the new wp-config.php</a>.';
									$this->messages[] = '<a href="">Reload the page</a> after updating the config file.';
								}
							}
						}
						else
						{
							$this->messages[] = '<strong>ERROR:</strong> Not all tables have been copied successfully.';
						}
					}
				}

				break;
			case 'db prefix remove old':
				if ( $wpdb->prefix != 'wp_' )
				{
					$tables = $wpdb->get_results('SHOW TABLES LIKE "wp_%"', ARRAY_N);
					
					if ( $tables )
					{
						$tablesDropped = array();
						
						foreach ( $tables as $table )
						{
							$table = $table[0];
							
							$r = $wpdb->query('DROP TABLE `' . $table . '`;');
							
							if ( $r === FALSE )
							{
								$this->messages[] = '<strong>ERROR:</strong> Could not drop table "' . $table . '".';
							}
							else
							{
								$tablesDropped[] = $table;
							}
						}

						if ( count($tablesDropped) == count($tables) )
						{
							$this->messages[] = 'Old tables have been removed successfully.';
						}
						else
						{
							$this->messages[] = '<strong>ERROR:</strong> Not all old tables have been removed successfully.';
						}
					}
				}

				break;
			case 'admin username':
				if ( isset($_POST['st_username']) )
				{
					$sql = '
						UPDATE `' . $wpdb->users . '` SET
							`user_login` = "' . $wpdb->escape($_POST['st_username']) . '"
						WHERE
							`ID` = 1';
          
					$r = $wpdb->query($sql);

					if ( $r === FALSE )
					{
						$this->messages[] = '<strong>ERROR:</strong> Could not change the admin username.';
					}
					else
					{
						$this->messages[] = 'The admin username has been changed to "' . wp_specialchars($_POST['st_username']) . '".';
					}
				}

				break;
			case 'ssl':
				update_option('st_force_ssl', !empty($_POST['st_force_ssl']) ? 1 : 0);

				if ( !empty($_POST['st_force_ssl']) )
				{
					$this->messages[] = 'Force SSL has been enabled.';
				}
				else
				{
					$this->messages[] = 'Force SSL has been disabled.';
				}

				break;
			case 'xss scan':
				$tables = $wpdb->get_results('SHOW TABLES LIKE "' . $wpdb->prefix . '%";', ARRAY_N);

				if ( $tables )
				{
					foreach ( $tables as $table )
					{
						$table = $table[0];
						
						$columns = array();
						
						$columns = $wpdb->get_results('SHOW COLUMNS FROM `' . $table . '`;', ARRAY_N);
						
						if ( $columns )
						{
							foreach ( $columns as $i => $column )
							{
								$columns[$i] = $column[0];
							}
						}
						
						$sql = '
							SELECT
								*
							FROM `' . $table . '`
							WHERE
								`' . implode('` REGEXP "' . $wpdb->escape($this->xssRegex) . '" OR `', $columns) . '` REGEXP "' . $wpdb->escape($this->xssRegex) . '"
							';
						
						$r = $wpdb->get_results($sql, ARRAY_A);
						
						if ( $r )
						{
							$this->potentialXss[$table] = array();
							
							foreach ( $r as $i => $columns2 )
							{
								if ( empty($this->potentialXss[$table]['columns']) )
								{
									$this->potentialXss[$table]['columns'] = array_keys($columns2);
									$this->potentialXss[$table]['values']  = array();
								}

								foreach ( $columns2 as $column2 => $value )
								{
									$this->potentialXss[$table]['values'][$i][$column2] = $value;
								}
							}							
						}
					}
				}

				break;
			case 'reset passwords':
				$sql = '
					SELECT
						`user_login`
					FROM `' . $wpdb->prefix . 'users`
					';
				
				$r = $wpdb->get_results($sql, ARRAY_A);
				if ( $r )
				{
					foreach ( $r as $d )
					{
						$login = $d['user_login'];

						$key = $wpdb->get_var($wpdb->prepare('SELECT `user_activation_key` FROM `' . $wpdb->users . '` WHERE user_login = %s', $login));
              
						if ( empty($key) )
						{         
							// Generate something random for a key...
							$key = wp_generate_password(20, false);
							
							do_action('retrieve_password_key', $user_login, $key);

							// Now insert the new md5 key into the db
							$wpdb->update($wpdb->users, array('user_activation_key' => $key), array('user_login' => $user_login));
						}
            
						$user = $wpdb->get_row($wpdb->prepare('SELECT * FROM `' . $wpdb->users . '` WHERE `user_activation_key` = %s AND `user_login` = %s', $key, $login));

						if ( !empty( $user ) )
						{  
							// Generate something random for a password...
							$new_pass = wp_generate_password();

							do_action('password_reset', $user, $new_pass);

							wp_set_password($new_pass, $user->ID);

							update_usermeta($user->ID, 'default_password_nag', true); //Set up the Password change nag.

							$message =
								__('For security reasons, your password has been reset.') . "\r\n\r\n" .
								sprintf(__('Username: %s'), $user->user_login) . "\r\n" .
								sprintf(__('Password: %s'), $new_pass) . "\r\n" .
								site_url('wp-login.php', 'login') . "\r\n"
								;

							$title = sprintf(__('[%s] Your new password'), get_option('blogname'));

							$title   = apply_filters('password_reset_title',   $title);
							$message = apply_filters('password_reset_message', $message, $new_pass);

							if ( $message && !wp_mail($user->user_email, $title, $message) )
							{
								die('<p>' . __('The e-mail could not be sent.') . "<br />\n" . __('Possible reason: your host may have disabled the mail() function...') . '</p>');
							}

							wp_password_change_notification($user);
						}
					}
				}

				break;
		}
	}

	function options_page()
	{
		add_management_page('Security Tools', 'MJP Security Tools', 'manage_options', __FILE__, array($this, 'options'));
	}

	function options()
	{
		global $wpdb;
		
		$this->updateCore = get_transient('update_core');
		
		// POST requests log		
		// Delete old entries
		$sql = '
			DELETE
				lp.*
			FROM `' . $wpdb->prefix . 'st_log_post` AS lp
			LEFT JOIN (
				SELECT
					`id`
				FROM `' . $wpdb->prefix . 'st_log_post`
				ORDER BY `id` DESC
				LIMIT 1000
				) AS recent ON lp.id = recent.id
			WHERE
				recent.id IS NULL
			;';

		$wpdb->query($sql);

		// Get latest entries
		$sql = '
			SELECT
				*
			FROM `' . $wpdb->prefix . 'st_log_post`
			ORDER BY `id` DESC
			LIMIT 100
			;';

		$this->postRequests = $wpdb->get_results($sql, ARRAY_A);

		if ( $this->postRequests )
		{
			foreach ( $this->postRequests as $i => $postRequest )
			{
				$this->postRequests[$i]['data'] = unserialize($postRequest['data']);
			}
		}

		// Failed logins log		
		// Delete old entries
		$sql = '
			DELETE
				lfl.*
			FROM `' . $wpdb->prefix . 'st_log_failed_logins` AS lfl
			LEFT JOIN (
				SELECT
					`id`
				FROM `' . $wpdb->prefix . 'st_log_failed_logins`
				ORDER BY `id` DESC
				LIMIT 1000
				) AS recent ON lfl.id = recent.id
			WHERE
				recent.id IS NULL
			;';

		$wpdb->query($sql);

		// Get latest entries
		$sql = '
			SELECT
				*
			FROM `' . $wpdb->prefix . 'st_log_failed_logins`
			ORDER BY `id` DESC
			LIMIT 100
			;';

		$this->failedLogins = $wpdb->get_results($sql, ARRAY_A);

		// Files		
		$files = $this->files_get_recursive('', ABSPATH);

		$this->files = $this->files_list_recursive($files);

		$this->files_get_status($this->files);

		// Database
		global $wpdb;

		$this->dbPrefix = $wpdb->prefix;

		if ( $wpdb->prefix != 'wp_' )
		{
			$r = $wpdb->get_results('SHOW TABLES LIKE "wp_%"', ARRAY_N);
			
			if ( $r )
			{
				$this->oldTables = TRUE;
			}
		}

		// Administration
		$admin = get_userdata(1);

		$this->adminUsername = $admin->user_login;
	
		require($this->pluginPath . 'admin_options.php');
	}
	
	function login_failed($username)
	{
		global $wpdb;

		$r = $wpdb->get_var('SHOW TABLES LIKE "' . $wpdb->prefix . 'st_log_failed_logins"');

		if ( $r )
		{
			$sql = '
				INSERT INTO `' . $wpdb->prefix . 'st_log_failed_logins` (
					`datetime`,
					`username`,
					`ip_addr`,
					`agent`
					)
				VALUES (
					NOW(),
					"' . $wpdb->escape($username) . '",
					"' . $wpdb->escape($_SERVER['REMOTE_ADDR']) . '",
					"' . ( isset($_SERVER['HTTP_USER_AGENT']) ? $wpdb->escape($_SERVER['HTTP_USER_AGENT']) : '' ) . '"
					)
				;';

			$wpdb->query($sql);
		}
	}

	function login_threshold($user)
	{
		global $wpdb;
		
		$sql = '
			SELECT
				*
			FROM `' . $wpdb->prefix . 'st_log_failed_logins`
			WHERE
				`username` = "' . $wpdb->escape($user->user_login) . '" AND
				`datetime` > DATE_SUB(NOW(), INTERVAL 10 SECOND)
			LIMIT 1
			;';

		$r = $wpdb->get_results($sql, ARRAY_A);

		if ( $r )
		{
			$error = new WP_Error();

			$error->add('login_threshold', '<strong>ERROR:</strong> To many login attempts. Please try again in a few seconds (this is to prevent malicious programs from guessing your password).');

			return $error;
		}

		return $user;
	}

	function profile_update($errors)
	{
		if ( $_POST['pass1'] )
		{
			if ( strlen($_POST['pass1']) < 8 || !preg_match('/[a-z]/i', $_POST['pass1']) || !preg_match('/[0-9]/', $_POST['pass1']) )
			{			
				$errors->add('blah', __('<strong>ERROR</strong>: Your password should be at least 8 characters and contain letters and numbers.'));
			}
		}
	}

	function generator()
	{
		// Don't show the version number
		return '<meta name="generator" content="WordPress" />';
	}
	
	function hidden_config()
	{
      if (file_exists(ABSPATH.'/wp-config.php'))
          return false;
      else
          return true;
  }

	private function files_get_recursive($dir, $homeDir, $files = array())
	{
		$files = array();
		
		if ( $handle = opendir($homeDir . $dir) )
		{
			while ( ( $file = readdir($handle) ) !== FALSE )
			{
				//if ( $file != '.' && $file != '..' )
				if ( $file != '.' && $file != '..' && !preg_match('/^\./', $file) )
				{
					$owner     = posix_getpwuid(fileowner($homeDir . $dir . $file));
					$group     = posix_getpwuid(filegroup($homeDir . $dir . $file));
					$perms     = substr(sprintf('%o', fileperms($homeDir . $dir . $file)), - 4);
					$permsFull = $this->perms_to_full(fileperms($homeDir . $dir . $file));
					
					if ( is_dir($homeDir . $dir . $file) )
					{
						$files[] = array(
							'name'       => $file,
							'type'       => 'dir',
							'path'       => $dir . $file,
							'owner'      => $owner['name'],
							'group'      => $group['name'],
							'perms'      => $perms,
							'perms_full' => $permsFull,
							'contents'   => $this->files_get_recursive($dir . $file . '/', $homeDir, $files)
							);
					}
					else
					{
						$files[] = array(
							'name'       => $file,
							'type'       => 'file',
							'owner'      => $owner['name'],
							'group'      => $group['name'],
							'perms'      => $perms,
							'perms_full' => $permsFull,
							'path'       => $dir . $file
							);
					}
				}
			}

			closedir($handle);
		}
		
		usort($files, array('securityTools', 'sort_by_name'));

		return $files;
	}

	private function sort_by_name($a, $b)
	{
		return $a['name'] == $b['name'] ? 0 : ( $a['name'] < $b['name'] ? - 1 : 1 );
	}

	private function files_list_recursive($files, &$list = array(), $depth = 0)
	{
		foreach ( $files as $file )
		{
			$list[] = array(
				'name'       => $file['name'],
				'type'       => $file['type'],
				'owner'      => $file['owner'],
				'group'      => $file['group'],
				'perms'      => $file['perms'],
				'perms_full' => $file['perms_full'],
				'contents'   => $file['contents'],
				'path'       => $file['path'],
				'children'   => !empty($file['contents']) ? count($file['contents']) : 'empty',
				'depth'      => $depth
				);
			
			if ( $file['type'] == 'dir' )
			{
				$this->files_list_recursive($file['contents'], $list, ++ $depth);
		
				$depth --;
			}
		}

		return $list;
	}

	private function files_format_recursive($files, &$filesFormatted = FALSE, $depth = 0)
	{
		foreach ( $files as $file )
		{
			$filesFormatted .= '
				<tr>
					<td><code>' . $file['perms'] . ' ' . $file['perms_full'] . '</code></td>
					<td>' . $file['owner'] . '</td>
					<td>' . $file['group'] . '</td>
					<td><code>' . str_repeat('&nbsp;&nbsp;', $depth) . ( $file['type'] == 'dir' ? ' &gt;</code> <strong>' : '</code> ' ) . $file['name'] . ( $file['type'] == 'dir' ? '</strong>' : '' ) . '</td>
				</tr>
				';
			
			if ( $file['type'] == 'dir' )
			{
				$this->files_format_recursive($file['contents'], $filesFormatted, ++ $depth);
		
				$depth --;
			}
		}

		return $filesFormatted;
	}
	
	private function files_get_status(&$files)
	{
		foreach ( $files as $i => $file )
		{
			$status = array();
			
			if ( $file['name'] == '.svn' || $file['name'] == '_svn' )
			{
				$status[] = 'SVN working copy should never be on a production server';
			}
			
			if ( $file['type'] == 'dir' && $file['contents'] )
			{
				$index = FALSE;

				foreach ( $file['contents'] as $file2 )
				{
					if ( $file2['name'] == 'index.html' || $file2['name'] == 'index.php' )
					{
						$index = TRUE;
					}
				}

				if ( !$index )
				{
					$status[] = 'Missing index.html file';
				}
			}

			if ( $file['type'] == 'file' && ( int ) $file['perms'] > 644 )
			{
				$status[] = 'Permissions should be set to 0644';
			}
			
			if ( $file['type'] == 'dir' && ( int ) $file['perms'] > 755 )
			{
				$status[] = 'Permissions should be set to 0755';
			}
			
			if ( empty($status) )
			{
				$files[$i]['status'] = '<span style="color: #090;">&#x2714; Ok</span>';
				$files[$i]['select'] = FALSE;
			}
			else
			{
				$files[$i]['status'] = '<span style="color: #900;">&#x2718; ' . implode('<br/>&#x2718; ', $status) . '</span>';
				$files[$i]['select'] = TRUE;

				$this->filesIssues += count($status);
			}
		}
	}
	
	private function perms_to_full($perms)
	{
		if ( ( $perms & 0xC000 ) == 0xC000 )
		{
			// Socket
			$info = 's';
		}
		elseif ( ( $perms & 0xA000 ) == 0xA000 )
		{
			// Symbolic Link
			$info = 'l';
		}
		elseif ( ( $perms & 0x8000 ) == 0x8000 )
		{
			// Regular
			$info = '-';
		}
		elseif ( ( $perms & 0x6000 ) == 0x6000 )
		{
			// Block special
			$info = 'b';
		}
		elseif ( ( $perms & 0x4000 ) == 0x4000 )
		{
			// Directory
			$info = 'd';
		}
		elseif ( ( $perms & 0x2000 ) == 0x2000)
		{
			// Character special
			$info = 'c';
		}
		elseif ( ( $perms & 0x1000 ) == 0x1000 )
		{
			// FIFO pipe
			$info = 'p';
		}
		else
		{
			// Unknown
			$info = 'u';
		}

		// Owner
		$info .= ( ( $perms & 0x0100 ) ? 'r' : '-' );
		$info .= ( ( $perms & 0x0080 ) ? 'w' : '-' );
		$info .= ( ( $perms & 0x0040 ) ? ( ( $perms & 0x0800 ) ? 's' : 'x' ) : ( ( $perms & 0x0800 ) ? 'S' : '-' ) );

		// Group
		$info .= ( ( $perms & 0x0020 ) ? 'r' : '-' );
		$info .= ( ( $perms & 0x0010 ) ? 'w' : '-' );
		$info .= ( ( $perms & 0x0008 ) ? ( ( $perms & 0x0400 ) ? 's' : 'x' ) : ( ( $perms & 0x0400 ) ? 'S' : '-' ) );

		// World
		$info .= ( ( $perms & 0x0004 ) ? 'r' : '-' );
		$info .= ( ( $perms & 0x0002 ) ? 'w' : '-' );
		$info .= ( ( $perms & 0x0001 ) ? ( ( $perms & 0x0200 ) ? 't' : 'x' ) : ( ( $perms & 0x0200 ) ? 'T' : '-' ) );

		return $info;
	}
}
