<?php
/*
Plugin Name: MJP Security Tools     
Plugin URI: http://wp.zackdesign.biz/
Description: Make your WordPress installation more secure.
Author: ElbertF, zackdesign, MJP
Version: 1.1
Author URI: http://zackdesign.biz
*/

require_once('security_tools.class.php');

global $securityTools;

if ( class_exists('securityTools') ) $securityTools = new securityTools();

if ( isset($securityTools) )
{	
	$securityTools->pluginPath = str_replace('\\', '/', ABSPATH) . PLUGINDIR . '/' . dirname(plugin_basename(__FILE__)) . '/';

	add_action('init',                       array($securityTools, 'init'));
	add_action('admin_menu',                 array($securityTools, 'options_page'));
	add_action('wp_login_failed',            array($securityTools, 'login_failed'));
	add_action('wp_authenticate_user',       array($securityTools, 'login_threshold'));
	add_action('user_profile_update_errors', array($securityTools, 'profile_update'));
	add_action('admin_head',                 array($securityTools, 'head'));

	add_filter('the_generator', array($securityTools, 'generator'));

	register_activation_hook(__FILE__, array($securityTools, 'install'));
}
