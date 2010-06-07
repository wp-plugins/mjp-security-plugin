<div class="wrap">
	<div id="icon-tools" class="icon32">
		<br />
	</div>

	<h2>MJP Security Tools</h2>

	<?php if ( !empty($this->messages) ): ?>
	<div id="message" class="updated fade" style="background-color: rgb(255, 251, 204);">
		<p>
			<?php echo implode('</p><p>', $this->messages) ?>
		</p>
	</div>
	<?php endif ?>

	<br />

	<div id="tabs">
		<ul>
			<li><a href="#tabs-1"><strong>General</strong></a></li>
			<li><a href="#tabs-2"><strong>Recent POST requests</strong></a></li>
			<li><a href="#tabs-3"><strong>Recent failed login attempts</strong></a></li>
			<li><a href="#tabs-4"><strong>Files</strong></a></li> 
		</ul>

		<script type="text/javascript">
			jQuery(function() {
				jQuery("#tabs").tabs();   
			});
		</script>

		<div id="tabs-2">
			<p>
				A <em>POST request</em> contains information which is usually send through a form on the website and can be used in <a href="http://en.wikipedia.org/wiki/Cross-site_request_forgery">CSRF</a> or other attacks.
			</p>

			<table class="widefat">
				<thead>
					<tr>
						<th style="width: 12em;">Date and time</th>
						<th style="width: 12em;">Keys</th>
						<th>Values</th>
						<th>Request URI</th>
						<th style="width: 12em;">IP address</th>
						<th>User agent</th>
					</tr>
				</thead>
				<tbody>
					<?php if ( $this->postRequests ): ?>
					<?php foreach ( $this->postRequests as $postRequest ): ?>
					<tr>
						<td><?php echo $postRequest['datetime'] ?></td>
						<td>
							<?php if ( $postRequest['data'] ): ?>
							<?php foreach ( $postRequest['data'] as $k => $v ): ?>
							<?php echo wp_specialchars($k) ?><br />
							<?php endforeach ?>
							<?php endif ?>
						</td>
						<td>
							<?php if ( $postRequest['data'] ): ?>
							<?php foreach ( $postRequest['data'] as $k => $v ): ?>
							<?php echo wp_specialchars($v) ?><br />
							<?php endforeach ?>
							<?php endif ?>
						</td>
						<td><a href="<?php echo $postRequest['url'] ?>"><?php echo $postRequest['url'] ?></a></td>
						<td><?php echo wp_specialchars($postRequest['ip_addr']) ?></td>
						<td><?php echo wp_specialchars($postRequest['agent']) ?></td>
					</tr>
					<?php endforeach ?>
					<?php endif ?>
				</tbody>
			</table>
		</div>

		<div id="tabs-3"
			<table class="widefat">
				<thead>
					<tr>
						<th style="width: 12em;">Date and time</th>
						<th style="width: 12em;">Username</th>
						<th style="width: 12em;">IP address</th>
						<th>User agent</th>
					</tr>
				</thead>
				<tbody>
					<?php if ( $this->failedLogins ): ?>
					<?php foreach ( $this->failedLogins as $failedLogin ): ?>
					<tr>
						<td><?php echo $failedLogin['datetime'] ?></td>
						<td><?php echo wp_specialchars($failedLogin['username']) ?></td>
						<td><?php echo wp_specialchars($failedLogin['ip_addr']) ?></td>
						<td><?php echo wp_specialchars($failedLogin['agent']) ?></td>
					</tr>
					<?php endforeach ?>
					<?php endif ?>
				</tbody>
			</table>
		</div>

		<div id="tabs-4">
			<form method="post" action="">
				<?php if ( $this->filesIssues ): ?>
				<p style="color: #900;">
					&#x2718;  <?php echo $this->filesIssues . ( $this->filesIssues == 1 ? ' issue' : ' issues' ) . ' found.' ?>
				</p>
				<?php else: ?>
				<p style="color: #090;">
					&#x2714; No issues here!
				</p>
				<?php endif ?>

				<table class="widefat fixed">
					<thead>
						<tr>
							<th style="width: 12em;">Permissions</th>
							<th style="width: 12em;">Owner</th>
							<th style="width: 12em;">Group</th>
							<th>File</th>
							<th>Status</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $this->files as $file ): ?>
						<tr title="<?php echo $file['path'] ?>">
							<td><code><?php echo $file['perms'] . ' ' . $file['perms_full'] ?></code></td>
							<td><?php echo $file['owner'] ?></td>
							<td><?php echo $file['group'] ?></td>
							<td>
								<code><?php echo str_repeat('&nbsp;&nbsp;', $file['depth']) . ( $file['type'] == 'dir' ? '&nbsp;&gt;</code>&nbsp;<strong>' : '</code>&nbsp;' ) . $file['name'] . ( $file['type'] == 'dir' ? '</strong> - ' . $file['children'] . ( $file['children'] == 1 ? ' file' : ' files' ) : '' ) ?>
							</td>
							<td><?php echo $file['status'] ?></td>
						</tr>
						<?php endforeach ?>
					</tbody>
					</table>
			</form>
		</div>

		<div id="tabs-1">
			<div  id="poststuff">
				<div class="postbox">
					<div title="Click to toggle" class="handlediv"><br /></div>
					
					<h3 class="hndle">
						<span>Installation</span>
					</h3>
					
					<div class="inside">
						<h4>Wordpress Version</h4>
						
						<p>
							You should always have the latest version of WordPress installed.
						</p>

						<?php if ( $this->updateCore->updates[0]->current != $this->updateCore->version_checked ): ?>
						<p style="color: #900;">
							&#x2718; There is a newer version of WordPress available (version <?php echo $this->updateCore->version_checked ?>).
						</p>
						<?php else: ?>
						<p style="color: #090;">
							&#x2714; No issues here!
						</p>
						<?php endif ?>
						
						
						<h4>Hidden Configuration file</h4>

            <?php if ($this->hidden_config()) : ?>
            <p style="color: #090;">
							&#x2714; No issues here!
						</p>
            <?php else : ?>

            <p style="color: #900;">
							&#x2718; See if you can hide wp-config.php one directory above your WP install.
						</p>

						<p>
							From <a href="http://codex.wordpress.org/Hardening_WordPress#Securing_wp-config.php">Securing wp-config.php</a>:
						</p>

            <p>You can move the <tt>wp-config.php</tt> file to the directory above your WordPress install.  This means for a site installed in the root of your webspace, you can store <tt>wp-config.php</tt> outside the web-root folder.  Note that <tt>wp-config.php</tt> can be stored ONE directory level above the WordPress (where wp-includes resides) installation.  </p>

            <?php endif; ?>

						<h4>Database table prefix</h4>
							
						<?php if ( $this->dbPrefix == 'wp_' ): ?>
						<form method="post" action="">
							<p style="color: #900;">
								&#x2718; The table prefix is predictable (currently set to 'wp_').
							</p>

							<p class="submit">
								<input type="submit" name="Submit" value="Randomize table prefix" class="button"/>
								<input type="hidden" name="st_action" value="db prefix"/>
								
								&nbsp; <strong>Steps:</strong> &nbsp; 1. Copy tables &nbsp; 2. Replace wp-config.php &nbsp; 3. Remove old tables if everything is working well.
							</p>
						</form>
						<?php elseif ( $this->oldTables ): ?>
						<form method="post" action="">
							<p style="color: #090;">
								&#x2714; The table prefix has been randomized.
							</p>

							<p style="color: #900;">
								&#x2718; The old tables are still present and should be removed.
							</p>

							<p class="submit">
								<input type="submit" name="Submit" value="Remove old tables" class="button"/>
								<input type="hidden" name="st_action" value="db prefix remove old"/>
							</p>
						</form>
						<?php else: ?>
						<p style="color: #090;">
							&#x2714; No issues here!
						</p>
						<?php endif ?>

					</div>
				</div>

				
					<div class="postbox">
						<div title="Click to toggle" class="handlediv"><br /></div>
						
						<h3 class="hndle">
							<span>Users</span>
						</h3>
						
						<div class="inside">
							<h4>Admin username</h4>
							
							<p>
								A predictable admin username makes the site more vulnerable to <a href="http://en.wikipedia.org/wiki/Brute_force_attack">Brute Force attacks</a>.
							</p>
							
							<?php if ( $this->adminUsername == 'admin' ): ?>
								<p style="color: #900;">
									&#x2718; The admin username is predictable (currently set to 'admin').
								</p>
							<?php else: ?>
							<p style="color: #090;">
								&#x2714; No issues here!
							</p>
							<?php endif ?>
         <form method="post" action="">
							<table class="form-table">
								<tr>
									<th>
										<label for="username">Username</label>
									</th>
									<td>
										<input id="username" class="regular-text" type="text" value="<?php echo $this->adminUsername ?>" name="st_username"/>
									</td>
								</tr>
								<tr>
									<td class="submit" colspan="2">
										<input type="submit" name="Submit" value="Change username" class="button"/>
										<input type="hidden" name="st_action" value="admin username"/>

										&nbsp; You will be prompted to re-login directly after changing the username.
									</td>
								</tr>
							</table>  
				</form>


							<h4>User passwords</h4>
							
							<p>
								User passwords should be reset periodically.
							</p>

							<?php if ( isset($_POST['st_action']) && $_POST['st_action'] == 'reset passwords' ): ?>
							<p style="color: #090;">
								&#x2714; All user passwords have been reset, users have been notified.
							</p>
							<?php endif ?>

							<form method="post" action="#passwords">
								<p class="submit">
									<input type="submit" name="Submit" value="Reset all user passwords" class="button"/>
									<input type="hidden" name="st_action" value="reset passwords"/>

									&nbsp; An e-mail will be send to all users with their new password.
								</p>
							</form>

						</div>
					</div>

				<div class="postbox">
					<div title="Click to toggle" class="handlediv"><br /></div>

					<a id="xss" name="xss"></a>

					<h3 class="hndle">
						<span>XSS (Cross Site Scripting)</span>
					</h3>

					<div class="inside">
						<h4>Script injection</h4>

						<p>
							The database should be regularly checked for possible <a href="http://en.wikipedia.org/wiki/Cross-site_scripting">XSS</a> issues.
							It is important to fix these issues immediately, if you don't know how it is strongly recommended to find someone who does.
							If potentially harmful scripts are found they will be highlighted in red.
						</p>

						<?php if ( !empty($this->potentialXss) ): ?>
						<p style="color: #900;">
							&#x2718; Potentially harmful scripts have been found.
						</p>

						<?php foreach ( $this->potentialXss as $name => $table ): ?>

						<p>
							<strong><?php echo $name ?></strong>
						</p>
						
						<table class="widefat fixed">
							<thead>
								<tr>
									<?php foreach ( $table['columns'] as $column ): ?>
									<th>
										<?php echo $column ?>
									</th>
									<?php endforeach ?>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $table['values'] as $i => $d ): ?>
								<tr>
									<?php foreach ( $d as $v ): ?>
									<td>
										<?php if ( preg_match('/' . $this->xssRegex . '/i', $v) ): ?>
										<span style="color: #900";>
											<?php echo str_replace('&gt;&gt;&gt;', '<span style="color: #FFF; background: #900;">', str_replace('&lt;&lt;&lt;', '</span>', wp_specialchars(preg_replace('/' . $this->xssRegex . '/', '>>>$1<<<', $v)))) ?>
										</span>
										<?php else: ?>
										<span style="color: #090";>
											<?php echo wp_specialchars($v) ?>
										</span>
										<?php endif ?>
									</td>
									<?php endforeach ?>
								</tr>
								<?php endforeach ?>
							</tbody>
						</table>
						<?php endforeach ?>
						<?php elseif ( isset($_POST['st_action']) && $_POST['st_action'] == 'xss scan' ): ?>
						<p style="color: #090;">
							&#x2714; No issues here!
						</p>
						<?php endif ?>

						<form method="post" action="#xss">
							<p class="submit">
								<input type="submit" name="Submit" value="Scan the database for injected scripts" class="button"/>
								<input type="hidden" name="st_action" value="xss scan"/>
							</p>
						</form>
					</div>
				</div>
					
				<div class="postbox">
					<div title="Click to toggle" class="handlediv"><br /></div>
					
					<h3 class="hndle">
						<span>Encryption</span>
					</h3>
					
					<div class="inside">
						<h4>SSL</h4>
						
						<p>
							<a href="http://en.wikipedia.org/wiki/Transport_Layer_Security">SSL</a> is used to encrypt website traffic (including passwords) to prevent <a href="http://en.wikipedia.org/wiki/Man-in-the-middle_attack">MITM attacks</a>. Please be aware that if you do not currently have SSL installed or working on your server setting this option to on will lock you out until you FTP in and rename the plugin folder or comment out the plugin SSL directives. 
						</p>

						<?php if ( substr(get_option('siteurl'), 0, 8) != 'https://' ): ?>
						<p style="color: #900;">
							&#x2718; SSL is not in use.
						</p>
						<?php else: ?>
						<p style="color: #090;">
							&#x2714; No issues here!
						</p>
						<?php endif ?>

						<table class="form-table">
							<tr>
								<th>
									<label for="force_ssl">Force SLL (always use https://)</label>
								</th>
								<td>
									<input id="force_ssl" class="regular-text" type="checkbox" value="1"<?php echo ( isset($_POST['st_force_ssl']) ? $_POST['st_force_ssl'] : get_option('st_force_ssl') ) ? ' checked="checked"' : '' ?> name="st_force_ssl"/>
								</td>
							</tr>
							<tr>
								<td class="submit" colspan="2">
									<input type="submit" name="Submit" value="Save" class="button"/>
									<input type="hidden" name="st_action" value="ssl"/>
								</td>
							</tr>
						</table>
						
						<p>
							More information: <a href="http://codex.wordpress.org/Administration_Over_SSL">Administration over SSL</a>.
						</p>
					</div>
				</div>
			
				<div class="postbox">
					<div title="Click to toggle" class="handlediv"><br /></div>

					<h3 class="hndle">
						<span>.htaccess Authorisation</span>
					</h3>

					<div class="inside">
						<h4>.htaccess</h4>

						<p>
							You can shield the entire <code>wp-admin</code> directory with an extra password which is managed by the Apache web server (required). This will stop attacks before they
							reach the admin section of the site.
						</p>
						
						<p>
							Create a file named <code>.htaccess</code> in the <code>wp-admin</code> directory with the following text (if the file already exists, just add it at the bottom of the file):
						</p>

						<textarea rows="4" cols="80" onfocus="this.select();">AuthType Basic
AuthName "Authentication required"
AuthUserFile <?php echo ABSPATH ?>wp-admin/.htpasswd
Require valid-user</textarea>

						<p>
							Make sure the permssions of the file are set to <code>chmod 0644</code>.
						</p>
						
						<h4>.htpasswd</h4>

						<p>
							Choose a filename and password.
						</p>
						
						<table class="form-table">
							<tbody>
								<tr>
									<th>
										<label for="ht_username">Username</label>
									</th>
									<td>
										<input type="text" class="regular-text" id="ht_username" onkeyup="ht_update();">
									</td>
								</tr>
								<tr>
									<th>
										<label for="ht_password">Password</label>
									</th>
									<td>
										<input type="text" class="regular-text" id="ht_password" onkeyup="ht_update();">
									</td>
								</tr>
							</tbody>
						</table>

						<p>
							Now create a file name <code>.htpasswd</code> in the <code>wp-admin</code> directory with the following text:
						</p>
						
						<input type="text" class="regular-text" id="htpasswd" onfocus="this.select();"></textarea>
						
						<p>
							Make sure the permssions of the file are set to <code>chmod 0640</code>.
						</p>

						<p>
							You will now be prompted for this username and password when you access the <code>wp-admin</code> directory.
						</p>

						<script type="text/javascript">
							var saltArray = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=][';/.,<>?:{}+_)(*&^%$#@!`~";

							function ht_update()
							{
								var
									e        = document.getElementById('htpasswd'),
									username = document.getElementById('ht_username').value,
									password = document.getElementById('ht_password').value
									;

								var maxIndex = saltArray.length;
								
								var salt = saltArray[Math.floor(Math.random() * maxIndex)] + saltArray[Math.floor(Math.random() * maxIndex)];
								
								e.value = username + ( password ? ':' + Javacrypt.crypt(salt, password)[0] : '' );
							}
						</script>
					</div>
				</div>
			</div>
		</div>
	</div>

	<h3>About</h3>

	<p>
		This plugin attempts to fix common security issues found in WordPress installations.
	</p>

	<h4>Features</h4>

	<ul style="list-style: disc inside; padding-left: 2em; margin: 1em 0;">
		<li>Scan the database for possible XSS issues.</li>
		<li>Limit login attempts to one per ten seconds per user.</li>
		<li>Check all file permissions.</li>
		<li>Check for presence of index.html files in all directories.</li>
		<li>Check if WordPress is up-to-date.</li>
		<li>Remove the version number from HTML source.</li>
		<li>Log all POST requests.</li>
		<li>Log all failed login attempts.</li>
		<li>Change the admin username.</li>
		<li>Randomize the database table prefix.</li>
		<li>Require stronger passwords.</li>
		<li>Detect SSL.</li>
	</ul>
	
	<p>
		More information about securing WordPress can be found on the WordPress Codex: <a href="http://codex.wordpress.org/Hardening_WordPress">Hardening WordPress</a>.
	</p>
</div>

<script type="text/javascript">
	/***************************************************************
	 *                                                             *
	 *      JAVACRYPT: CLIENT-SIDE crypt(3) USING JAVASCRIPT       *
	 *                                                             *
	 ***************************************************************
	 *                                                             *
	 *  This Javascript allows you to calculate the encrypted      *
	 *  password generated by the UNIX function crypt(3) on your   *
	 *  computer without using an online script in PHP, PERL,      *
	 *  shell, or any other server-side script.  The only changes  *
	 *  you need make in this are in function dP(), which is right *
	 *  below the end of this comment.  Refer to the directions    *
	 *  there for details.                                         *
	 *                                                             *
	 *  I wish I could take full credit for this script, but there *
	 *  are several people who deserve most of the credit          *
	 *                                                             *
	 *  First and foremost, I thank John F. Dumas for writing      *
	 *  jcrypt.java, a Java-based implementation of crypt(3) and   *
	 *  from which this Javascript is heavily based (actually, I   *
	 *  just did a direct port from his code, using Sun's tutorial *
	 *  and my knowledge of Javascript).  I additionally thank     *
	 *  Eric Young for writing the C code off which Dumas based    *
	 *  his script.  Finally, thanks goes to the original writers  *
	 *  of crypt(3), whoever they are.                             *
	 *                                                             *
	 *  If you have questions, I suggest you ask John Dumas about  *
	 *  them, as I have no real idea what any of this code does.   *
	 *  Base the questions off his source code, as Javascript and  *
	 *  Java are (in basic operators) nearly identical.            *
	 *                                                             *
	 *  jcrypt.java source code can be found at:                   *
	 *  http://locutus.kingwoodcable.com/jfd/crypt.html            *
	 *                                                             *
	 ***************************************************************/

	function dP(){
		if(confirm("Click OK if you have a salt.")) salt=prompt("Please input your two-character string [./a-zA-z0-9]:",'');
		else salt='';
		pw_salt=this.crypt(salt,document.CRYPT.PW.value);  // Change CRYPT.PW to the name of the form, then a
										   // period, then the name of the text box that
										   // contains the password to encrypt (lower/uppercase matters!)
										   // e.g., this:
										   //      <form name=hK><input type=text name=pWd></form>
										   // yields this:
										   //      pw_salt=this.crypt(salt,document.hK.pWd.value);


		document.CRYPT.ENC_PW.value=pw_salt[0];		   // For this line and the next, change CRYPT.ENC_PW and
		document.CRYPT.Salt.value=pw_salt[1];		   // CRYPT.Salt to the name of the form, then a period, then
										   // the name of the text box to display the encrypted
										   // password in or the salt used, respectively, as shown above.
		return false;
	}

	function bTU(b){
		  value=Math.floor(b);
		  return (value>=0?value:value+256);
	}
	function fBTI(b,offset){
		  value=this.byteToUnsigned(b[offset++]);
		  value|=(this.byteToUnsigned(b[offset++])<<8);
		  value|=(this.byteToUnsigned(b[offset++])<<16);
		  value|=(this.byteToUnsigned(b[offset++])<<24);
		  return value;
	}
	function iTFB(iValue,b,offset){
		  b[offset++]=((iValue)&0xff);
		  b[offset++]=((iValue>>>8)&0xff);
		  b[offset++]=((iValue>>>16)&0xff);
		  b[offset++]=((iValue>>>24)&0xff);
	}
	function P_P(a,b,n,m,results){
		  t=((a>>>n)^b)&m;
		  a^=t<<n;
		  b^=t;
		  results[0]=a;
		  results[1]=b;
	}
	function H_P(a,n,m){
		  t=((a<<(16-n))^a)&m;
		  a=a^t^(t>>>(16-n));
		  return a;
	}
	function d_s_k(key){
		  schedule=new Array(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
		  c=this.fourBytesToInt(key,0);
		  d=this.fourBytesToInt(key,4);
		  results=new Array(0,0);
		  this.PERM_OP(d,c,4,0x0f0f0f0f,results);
		  d=results[0];c=results[1];
		  c=this.HPERM_OP(c,-2,0xcccc0000);
		  d=this.HPERM_OP(d,-2,0xcccc0000);
		  this.PERM_OP(d,c,1,0x55555555,results);
		  d=results[0];c=results[1];
		  this.PERM_OP(c,d,8,0x00ff00ff,results);
		  c=results[0];d=results[1];
		  this.PERM_OP(d,c,1,0x55555555,results);
		  d=results[0];c=results[1];
		  d=(((d&0x000000ff)<<16)|(d&0x0000ff00)|((d&0x00ff0000)>>>16)|((c&0xf0000000)>>>4));
		  c&=0x0fffffff;
		  s=0;t=0;
		  j=0;
		  for(i=0;i<this.ITERATIONS;i++){
			 if(this.shifts2[i]){
				c=(c>>>2)|(c<<26);
				d=(d>>>2)|(d<<26);
			 }else{
				c=(c>>>1)|(c<<27);
				d=(d>>>1)|(d<<27);
			 }
			 c&=0x0fffffff;
			 d&=0x0fffffff;
			 s=this.skb[0][c&0x3f]|this.skb[1][((c>>>6)&0x03)|((c>>>7)&0x3c)]|this.skb[2][((c>>>13)&0x0f)|((c>>>14)&0x30)]|this.skb[3][((c>>>20)&0x01)|((c>>>21)&0x06)|((c>>>22)&0x38)];
			 t=this.skb[4][d&0x3f]|this.skb[5][((d>>>7)&0x03)|((d>>>8)&0x3c)]|this.skb[6][(d>>>15)&0x3f]|this.skb[7][((d>>>21)&0x0f)|((d>>>22)&0x30)];
			 schedule[j++]=((t<< 16)|(s&0x0000ffff))&0xffffffff;
			 s=((s>>>16)|(t&0xffff0000));
			 s=(s<<4)|(s>>>28);
			 schedule[j++]=s&0xffffffff;
		  }
		  return schedule;
	}
	function D_E(L,R,S,E0,E1,s){
		  v=R^(R>>>16);
		  u=v&E0;
		  v=v&E1;
		  u=(u^(u<<16))^R^s[S];
		  t=(v^(v<<16))^R^s[S+1];
		  t=(t>>>4)|(t<<28);
		  L^=this.SPtrans[1][t&0x3f]|this.SPtrans[3][(t>>>8)&0x3f]|this.SPtrans[5][(t>>>16)&0x3f]|this.SPtrans[7][(t>>>24)&0x3f]|this.SPtrans[0][u&0x3f]|this.SPtrans[2][(u>>>8)&0x3f]|this.SPtrans[4][(u>>>16)&0x3f]|this.SPtrans[6][(u>>>24)&0x3f];
		  return L;
	}
	function bdy(schedule,Eswap0,Eswap1) {
		left=0;
		right=0;
		t=0;
		  for(j=0;j<25;j++){
			 for(i=0;i<this.ITERATIONS*2;i+=4){
				left=this.D_ENCRYPT(left, right,i,Eswap0,Eswap1,schedule);
				right=this.D_ENCRYPT(right,left,i+2,Eswap0,Eswap1,schedule);
			 }
			 t=left; 
			 left=right; 
			 right=t;
		  }
		  t=right;
		  right=(left>>>1)|(left<<31);
		  left=(t>>>1)|(t<<31);
		  left&=0xffffffff;
		  right&=0xffffffff;
		  results=new Array(0,0);
		  this.PERM_OP(right,left,1,0x55555555,results); 
		  right=results[0];left=results[1];
		  this.PERM_OP(left,right,8,0x00ff00ff,results); 
		  left=results[0];right=results[1];
		  this.PERM_OP(right,left,2,0x33333333,results); 
		  right=results[0];left=results[1];
		  this.PERM_OP(left,right,16,0x0000ffff,results);
		  left=results[0];right=results[1];
		  this.PERM_OP(right,left,4,0x0f0f0f0f,results);
		  right=results[0];left=results[1];
		  out=new Array(0,0);
		  out[0]=left;out[1]=right;
		  return out;
	}
	function rC(){ return this.GOODCHARS[Math.floor(64*Math.random())]; }
	function cript(salt,original){
		if(salt.length>=2) salt=salt.substring(0,2);
		while(salt.length<2) salt+=this.randChar();
		re=new RegExp("[^./a-zA-Z0-9]","g");
		if(re.test(salt)) salt=this.randChar()+this.randChar();
		charZero=salt.charAt(0)+'';
		  charOne=salt.charAt(1)+'';
		ccZ=charZero.charCodeAt(0);
		ccO=charOne.charCodeAt(0);
		buffer=charZero+charOne+"           ";
		  Eswap0=this.con_salt[ccZ];
		  Eswap1=this.con_salt[ccO]<<4;
		  key=new Array(0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0);
		  for(i=0;i<key.length&&i<original.length;i++){
			 iChar=original.charCodeAt(i);
			 key[i]=iChar<<1;
		  }
		  schedule=this.des_set_key(key);
		  out=this.body(schedule,Eswap0,Eswap1);
		  b=new Array(0,0,0,0,0,0,0,0,0);
		  this.intToFourBytes(out[0],b,0);
		  this.intToFourBytes(out[1],b,4);
		  b[8]=0;
		  for(i=2,y=0,u=0x80;i<13;i++){
			 for(j=0,c=0;j<6;j++){
				c<<=1;
				if((b[y]&u)!=0) c|=1;
				u>>>=1;
				if(u==0){
				   y++;
				   u=0x80;
				}
				buffer=buffer.substring(0,i)+String.fromCharCode(this.cov_2char[c])+buffer.substring(i+1,buffer.length);
			 }
		  }
		ret=new Array(buffer,salt);
		  return ret;
	}

	function Crypt() {
	this.ITERATIONS=16;
	this.GOODCHARS=new Array(
		".","/","0","1","2","3","4","5","6","7",
		"8","9","A","B","C","D","E","F","G","H",
		"I","J","K","L","M","N","O","P","Q","R",
		"S","T","U","V","W","X","Y","Z","a","b",
		"c","d","e","f","g","h","i","j","k","l",
		"m","n","o","p","q","r","s","t","u","v",
		"w","x","y","z");
	this.con_salt=new Array(
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
		  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
		  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
		  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
		  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
		  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01, 
		  0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09, 
		  0x0A,0x0B,0x05,0x06,0x07,0x08,0x09,0x0A, 
		  0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12, 
		  0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A, 
		  0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22, 
		  0x23,0x24,0x25,0x20,0x21,0x22,0x23,0x24, 
		  0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C, 
		  0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34, 
		  0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C, 
		  0x3D,0x3E,0x3F,0x00,0x00,0x00,0x00,0x00 );
	this.shifts2=new Array(
		false,false,true,true,true,true,true,true,
		false,true, true,true,true,true,true,false );
	this.skb=new Array(0,0,0,0,0,0,0,0);
		this.skb[0]=new Array(
			 0x00000000,0x00000010,0x20000000,0x20000010, 
			 0x00010000,0x00010010,0x20010000,0x20010010, 
			 0x00000800,0x00000810,0x20000800,0x20000810, 
			 0x00010800,0x00010810,0x20010800,0x20010810, 
			 0x00000020,0x00000030,0x20000020,0x20000030, 
			 0x00010020,0x00010030,0x20010020,0x20010030, 
			 0x00000820,0x00000830,0x20000820,0x20000830, 
			 0x00010820,0x00010830,0x20010820,0x20010830, 
			 0x00080000,0x00080010,0x20080000,0x20080010, 
			 0x00090000,0x00090010,0x20090000,0x20090010, 
			 0x00080800,0x00080810,0x20080800,0x20080810, 
			 0x00090800,0x00090810,0x20090800,0x20090810, 
			 0x00080020,0x00080030,0x20080020,0x20080030, 
			 0x00090020,0x00090030,0x20090020,0x20090030, 
			 0x00080820,0x00080830,0x20080820,0x20080830, 
			 0x00090820,0x00090830,0x20090820,0x20090830 );
		this.skb[1]=new Array(
			 0x00000000,0x02000000,0x00002000,0x02002000, 
			 0x00200000,0x02200000,0x00202000,0x02202000, 
			 0x00000004,0x02000004,0x00002004,0x02002004, 
			 0x00200004,0x02200004,0x00202004,0x02202004, 
			 0x00000400,0x02000400,0x00002400,0x02002400, 
			 0x00200400,0x02200400,0x00202400,0x02202400, 
			 0x00000404,0x02000404,0x00002404,0x02002404, 
			 0x00200404,0x02200404,0x00202404,0x02202404, 
			 0x10000000,0x12000000,0x10002000,0x12002000, 
			 0x10200000,0x12200000,0x10202000,0x12202000, 
			 0x10000004,0x12000004,0x10002004,0x12002004, 
			 0x10200004,0x12200004,0x10202004,0x12202004, 
			 0x10000400,0x12000400,0x10002400,0x12002400, 
			 0x10200400,0x12200400,0x10202400,0x12202400, 
			 0x10000404,0x12000404,0x10002404,0x12002404, 
			 0x10200404,0x12200404,0x10202404,0x12202404 );
		this.skb[2]=new Array(
			 0x00000000,0x00000001,0x00040000,0x00040001, 
			 0x01000000,0x01000001,0x01040000,0x01040001, 
			 0x00000002,0x00000003,0x00040002,0x00040003, 
			 0x01000002,0x01000003,0x01040002,0x01040003, 
			 0x00000200,0x00000201,0x00040200,0x00040201, 
			 0x01000200,0x01000201,0x01040200,0x01040201, 
			 0x00000202,0x00000203,0x00040202,0x00040203, 
			 0x01000202,0x01000203,0x01040202,0x01040203, 
			 0x08000000,0x08000001,0x08040000,0x08040001, 
			 0x09000000,0x09000001,0x09040000,0x09040001, 
			 0x08000002,0x08000003,0x08040002,0x08040003, 
			 0x09000002,0x09000003,0x09040002,0x09040003, 
			 0x08000200,0x08000201,0x08040200,0x08040201, 
			 0x09000200,0x09000201,0x09040200,0x09040201, 
			 0x08000202,0x08000203,0x08040202,0x08040203, 
			 0x09000202,0x09000203,0x09040202,0x09040203 );
		this.skb[3]=new Array(
			 0x00000000,0x00100000,0x00000100,0x00100100, 
			 0x00000008,0x00100008,0x00000108,0x00100108, 
			 0x00001000,0x00101000,0x00001100,0x00101100, 
			 0x00001008,0x00101008,0x00001108,0x00101108, 
			 0x04000000,0x04100000,0x04000100,0x04100100, 
			 0x04000008,0x04100008,0x04000108,0x04100108, 
			 0x04001000,0x04101000,0x04001100,0x04101100, 
			 0x04001008,0x04101008,0x04001108,0x04101108, 
			 0x00020000,0x00120000,0x00020100,0x00120100, 
			 0x00020008,0x00120008,0x00020108,0x00120108, 
			 0x00021000,0x00121000,0x00021100,0x00121100, 
			 0x00021008,0x00121008,0x00021108,0x00121108, 
			 0x04020000,0x04120000,0x04020100,0x04120100, 
			 0x04020008,0x04120008,0x04020108,0x04120108, 
			 0x04021000,0x04121000,0x04021100,0x04121100, 
			 0x04021008,0x04121008,0x04021108,0x04121108 );
		this.skb[4]=new Array(
			 0x00000000,0x10000000,0x00010000,0x10010000, 
			 0x00000004,0x10000004,0x00010004,0x10010004, 
			 0x20000000,0x30000000,0x20010000,0x30010000, 
			 0x20000004,0x30000004,0x20010004,0x30010004, 
			 0x00100000,0x10100000,0x00110000,0x10110000, 
			 0x00100004,0x10100004,0x00110004,0x10110004, 
			 0x20100000,0x30100000,0x20110000,0x30110000, 
			 0x20100004,0x30100004,0x20110004,0x30110004, 
			 0x00001000,0x10001000,0x00011000,0x10011000, 
			 0x00001004,0x10001004,0x00011004,0x10011004, 
			 0x20001000,0x30001000,0x20011000,0x30011000, 
			 0x20001004,0x30001004,0x20011004,0x30011004, 
			 0x00101000,0x10101000,0x00111000,0x10111000, 
			 0x00101004,0x10101004,0x00111004,0x10111004, 
			 0x20101000,0x30101000,0x20111000,0x30111000, 
			 0x20101004,0x30101004,0x20111004,0x30111004 );
		this.skb[5]=new Array(
			 0x00000000,0x08000000,0x00000008,0x08000008, 
			 0x00000400,0x08000400,0x00000408,0x08000408, 
			 0x00020000,0x08020000,0x00020008,0x08020008, 
			 0x00020400,0x08020400,0x00020408,0x08020408, 
			 0x00000001,0x08000001,0x00000009,0x08000009, 
			 0x00000401,0x08000401,0x00000409,0x08000409, 
			 0x00020001,0x08020001,0x00020009,0x08020009, 
			 0x00020401,0x08020401,0x00020409,0x08020409, 
			 0x02000000,0x0A000000,0x02000008,0x0A000008, 
			 0x02000400,0x0A000400,0x02000408,0x0A000408, 
			 0x02020000,0x0A020000,0x02020008,0x0A020008, 
			 0x02020400,0x0A020400,0x02020408,0x0A020408, 
			 0x02000001,0x0A000001,0x02000009,0x0A000009, 
			 0x02000401,0x0A000401,0x02000409,0x0A000409, 
			 0x02020001,0x0A020001,0x02020009,0x0A020009, 
			 0x02020401,0x0A020401,0x02020409,0x0A020409 );
		this.skb[6]=new Array(
			 0x00000000,0x00000100,0x00080000,0x00080100, 
			 0x01000000,0x01000100,0x01080000,0x01080100, 
			 0x00000010,0x00000110,0x00080010,0x00080110, 
			 0x01000010,0x01000110,0x01080010,0x01080110, 
			 0x00200000,0x00200100,0x00280000,0x00280100, 
			 0x01200000,0x01200100,0x01280000,0x01280100, 
			 0x00200010,0x00200110,0x00280010,0x00280110, 
			 0x01200010,0x01200110,0x01280010,0x01280110, 
			 0x00000200,0x00000300,0x00080200,0x00080300, 
			 0x01000200,0x01000300,0x01080200,0x01080300, 
			 0x00000210,0x00000310,0x00080210,0x00080310, 
			 0x01000210,0x01000310,0x01080210,0x01080310, 
			 0x00200200,0x00200300,0x00280200,0x00280300, 
			 0x01200200,0x01200300,0x01280200,0x01280300, 
			 0x00200210,0x00200310,0x00280210,0x00280310, 
			 0x01200210,0x01200310,0x01280210,0x01280310 );
		this.skb[7]=new Array(
			 0x00000000,0x04000000,0x00040000,0x04040000, 
			 0x00000002,0x04000002,0x00040002,0x04040002, 
			 0x00002000,0x04002000,0x00042000,0x04042000, 
			 0x00002002,0x04002002,0x00042002,0x04042002, 
			 0x00000020,0x04000020,0x00040020,0x04040020, 
			 0x00000022,0x04000022,0x00040022,0x04040022, 
			 0x00002020,0x04002020,0x00042020,0x04042020, 
			 0x00002022,0x04002022,0x00042022,0x04042022, 
			 0x00000800,0x04000800,0x00040800,0x04040800, 
			 0x00000802,0x04000802,0x00040802,0x04040802, 
			 0x00002800,0x04002800,0x00042800,0x04042800, 
			 0x00002802,0x04002802,0x00042802,0x04042802, 
			 0x00000820,0x04000820,0x00040820,0x04040820, 
			 0x00000822,0x04000822,0x00040822,0x04040822, 
			 0x00002820,0x04002820,0x00042820,0x04042820, 
			 0x00002822,0x04002822,0x00042822,0x04042822 );
	this.SPtrans=new Array(0,0,0,0,0,0,0,0);
		this.SPtrans[0]=new Array(
			 0x00820200,0x00020000,0x80800000,0x80820200,
			 0x00800000,0x80020200,0x80020000,0x80800000,
			 0x80020200,0x00820200,0x00820000,0x80000200,
			 0x80800200,0x00800000,0x00000000,0x80020000,
			 0x00020000,0x80000000,0x00800200,0x00020200,
			 0x80820200,0x00820000,0x80000200,0x00800200,
			 0x80000000,0x00000200,0x00020200,0x80820000,
			 0x00000200,0x80800200,0x80820000,0x00000000,
			 0x00000000,0x80820200,0x00800200,0x80020000,
			 0x00820200,0x00020000,0x80000200,0x00800200,
			 0x80820000,0x00000200,0x00020200,0x80800000,
			 0x80020200,0x80000000,0x80800000,0x00820000,
			 0x80820200,0x00020200,0x00820000,0x80800200,
			 0x00800000,0x80000200,0x80020000,0x00000000,
			 0x00020000,0x00800000,0x80800200,0x00820200,
			 0x80000000,0x80820000,0x00000200,0x80020200 );
		this.SPtrans[1]=new Array(
			 0x10042004,0x00000000,0x00042000,0x10040000,
			 0x10000004,0x00002004,0x10002000,0x00042000,
			 0x00002000,0x10040004,0x00000004,0x10002000,
			 0x00040004,0x10042000,0x10040000,0x00000004,
			 0x00040000,0x10002004,0x10040004,0x00002000,
			 0x00042004,0x10000000,0x00000000,0x00040004,
			 0x10002004,0x00042004,0x10042000,0x10000004,
			 0x10000000,0x00040000,0x00002004,0x10042004,
			 0x00040004,0x10042000,0x10002000,0x00042004,
			 0x10042004,0x00040004,0x10000004,0x00000000,
			 0x10000000,0x00002004,0x00040000,0x10040004,
			 0x00002000,0x10000000,0x00042004,0x10002004,
			 0x10042000,0x00002000,0x00000000,0x10000004,
			 0x00000004,0x10042004,0x00042000,0x10040000,
			 0x10040004,0x00040000,0x00002004,0x10002000,
			 0x10002004,0x00000004,0x10040000,0x00042000 );
		this.SPtrans[2]=new Array(
			 0x41000000,0x01010040,0x00000040,0x41000040,
			 0x40010000,0x01000000,0x41000040,0x00010040,
			 0x01000040,0x00010000,0x01010000,0x40000000,
			 0x41010040,0x40000040,0x40000000,0x41010000,
			 0x00000000,0x40010000,0x01010040,0x00000040,
			 0x40000040,0x41010040,0x00010000,0x41000000,
			 0x41010000,0x01000040,0x40010040,0x01010000,
			 0x00010040,0x00000000,0x01000000,0x40010040,
			 0x01010040,0x00000040,0x40000000,0x00010000,
			 0x40000040,0x40010000,0x01010000,0x41000040,
			 0x00000000,0x01010040,0x00010040,0x41010000,
			 0x40010000,0x01000000,0x41010040,0x40000000,
			 0x40010040,0x41000000,0x01000000,0x41010040,
			 0x00010000,0x01000040,0x41000040,0x00010040,
			 0x01000040,0x00000000,0x41010000,0x40000040,
			 0x41000000,0x40010040,0x00000040,0x01010000 );
		this.SPtrans[3]=new Array(
			 0x00100402,0x04000400,0x00000002,0x04100402,
			 0x00000000,0x04100000,0x04000402,0x00100002,
			 0x04100400,0x04000002,0x04000000,0x00000402,
			 0x04000002,0x00100402,0x00100000,0x04000000,
			 0x04100002,0x00100400,0x00000400,0x00000002,
			 0x00100400,0x04000402,0x04100000,0x00000400,
			 0x00000402,0x00000000,0x00100002,0x04100400,
			 0x04000400,0x04100002,0x04100402,0x00100000,
			 0x04100002,0x00000402,0x00100000,0x04000002,
			 0x00100400,0x04000400,0x00000002,0x04100000,
			 0x04000402,0x00000000,0x00000400,0x00100002,
			 0x00000000,0x04100002,0x04100400,0x00000400,
			 0x04000000,0x04100402,0x00100402,0x00100000,
			 0x04100402,0x00000002,0x04000400,0x00100402,
			 0x00100002,0x00100400,0x04100000,0x04000402,
			 0x00000402,0x04000000,0x04000002,0x04100400 );
		this.SPtrans[4]=new Array(
			 0x02000000,0x00004000,0x00000100,0x02004108,
			 0x02004008,0x02000100,0x00004108,0x02004000,
			 0x00004000,0x00000008,0x02000008,0x00004100,
			 0x02000108,0x02004008,0x02004100,0x00000000,
			 0x00004100,0x02000000,0x00004008,0x00000108,
			 0x02000100,0x00004108,0x00000000,0x02000008,
			 0x00000008,0x02000108,0x02004108,0x00004008,
			 0x02004000,0x00000100,0x00000108,0x02004100,
			 0x02004100,0x02000108,0x00004008,0x02004000,
			 0x00004000,0x00000008,0x02000008,0x02000100,
			 0x02000000,0x00004100,0x02004108,0x00000000,
			 0x00004108,0x02000000,0x00000100,0x00004008,
			 0x02000108,0x00000100,0x00000000,0x02004108,
			 0x02004008,0x02004100,0x00000108,0x00004000,
			 0x00004100,0x02004008,0x02000100,0x00000108,
			 0x00000008,0x00004108,0x02004000,0x02000008 );

		this.SPtrans[5]=new Array(
			 0x20000010,0x00080010,0x00000000,0x20080800,
			 0x00080010,0x00000800,0x20000810,0x00080000,
			 0x00000810,0x20080810,0x00080800,0x20000000,
			 0x20000800,0x20000010,0x20080000,0x00080810,
			 0x00080000,0x20000810,0x20080010,0x00000000,
			 0x00000800,0x00000010,0x20080800,0x20080010,
			 0x20080810,0x20080000,0x20000000,0x00000810,
			 0x00000010,0x00080800,0x00080810,0x20000800,
			 0x00000810,0x20000000,0x20000800,0x00080810,
			 0x20080800,0x00080010,0x00000000,0x20000800,
			 0x20000000,0x00000800,0x20080010,0x00080000,
			 0x00080010,0x20080810,0x00080800,0x00000010,
			 0x20080810,0x00080800,0x00080000,0x20000810,
			 0x20000010,0x20080000,0x00080810,0x00000000,
			 0x00000800,0x20000010,0x20000810,0x20080800,
			 0x20080000,0x00000810,0x00000010,0x20080010 );
		this.SPtrans[6]=new Array(
			 0x00001000,0x00000080,0x00400080,0x00400001,
			 0x00401081,0x00001001,0x00001080,0x00000000,
			 0x00400000,0x00400081,0x00000081,0x00401000,
			 0x00000001,0x00401080,0x00401000,0x00000081,
			 0x00400081,0x00001000,0x00001001,0x00401081,
			 0x00000000,0x00400080,0x00400001,0x00001080,
			 0x00401001,0x00001081,0x00401080,0x00000001,
			 0x00001081,0x00401001,0x00000080,0x00400000,
			 0x00001081,0x00401000,0x00401001,0x00000081,
			 0x00001000,0x00000080,0x00400000,0x00401001,
			 0x00400081,0x00001081,0x00001080,0x00000000,
			 0x00000080,0x00400001,0x00000001,0x00400080,
			 0x00000000,0x00400081,0x00400080,0x00001080,
			 0x00000081,0x00001000,0x00401081,0x00400000,
			 0x00401080,0x00000001,0x00001001,0x00401081,
			 0x00400001,0x00401080,0x00401000,0x00001001 );
		this.SPtrans[7]=new Array(
			 0x08200020,0x08208000,0x00008020,0x00000000,
			 0x08008000,0x00200020,0x08200000,0x08208020,
			 0x00000020,0x08000000,0x00208000,0x00008020,
			 0x00208020,0x08008020,0x08000020,0x08200000,
			 0x00008000,0x00208020,0x00200020,0x08008000,
			 0x08208020,0x08000020,0x00000000,0x00208000,
			 0x08000000,0x00200000,0x08008020,0x08200020,
			 0x00200000,0x00008000,0x08208000,0x00000020,
			 0x00200000,0x00008000,0x08000020,0x08208020,
			 0x00008020,0x08000000,0x00000000,0x00208000,
			 0x08200020,0x08008020,0x08008000,0x00200020,
			 0x08208000,0x00000020,0x00200020,0x08008000,
			 0x08208020,0x00200000,0x08200000,0x08000020,
			 0x00208000,0x00008020,0x08008020,0x08200000,
			 0x00000020,0x08208000,0x00208020,0x00000000,
			 0x08000000,0x08200020,0x00008000,0x00208020 );
	this.cov_2char=new Array(
		  0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35, 
		  0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44, 
		  0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C, 
		  0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54, 
		  0x55,0x56,0x57,0x58,0x59,0x5A,0x61,0x62, 
		  0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A, 
		  0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72, 
		  0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A );
	this.byteToUnsigned=bTU;
	this.fourBytesToInt=fBTI;
	this.intToFourBytes=iTFB;
	this.PERM_OP=P_P;
	this.HPERM_OP=H_P;
	this.des_set_key=d_s_k;
	this.D_ENCRYPT=D_E;
	this.body=bdy;
	this.randChar=rC;
	this.crypt=cript;
	this.displayPassword=dP;
	}
	Javacrypt=new Crypt();
</script>