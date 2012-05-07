=== MJP Security Plugin ===
Contributors: zackdesign, ElbertF
http://wp.zackdesign.biz/category/plugins/mjp-security-plugin/
Donate link: http://www.zackdesign.biz/
Tags: security, xss, login, username, permissions, post, form, prefix, table, database, password, ssl
Requires at least: 2.8
Tested up to: 3.3.2
Stable tag: 1.1

MJP Security Tools is a plugin designed to fix a lot of Wordpress security issues, as well as providing extra support.

== Description ==
Note: This plugin requires PHP 5

Using Wordpress security docs as a guide we have targeted a lot of the issues and endeavoured to make the process of strengthening your WP installation as easy as possible by providing the information you need to be able to set things up.

Features:

    * Scan the database for possible XSS issues.
    * Limit login attempts to one per ten seconds per user.
    * Check all file permissions.
    * Check for presence of index.html files in all directories.
    * Check if WordPress is up-to-date.
    * Remove the version number from HTML source.
    * Log all POST requests.
    * Log all failed login attempts.
    * Change the admin username.
    * Randomize the database table prefix.
    * Require stronger passwords.
    * Detect SSH.

This plugin was commisioned by [MJ Penner Consulting](http://www.michaelpenner.com/ "MJ Penner Consulting") and released to the general public as a gesture of good will.

== Installation ==

1. Upload the 'mjjp-security-tools' folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
5. View the admin for the Security Tools in Tools - > Security Tools
5. Follow the prompts to help sort out your plugin security.

= Upgrade Information =

Please do not upgrade beyond v 1.0 if you are on Wordpress 2.8 - 2.9! 

== Screenshots ==

There are no screenshots currently available for this plugin.

== Frequently Asked Questions ==

= I Need HELP!!! =

That's what I'm here for. I do Wordpress sites for many people in a professional capacity and
can do the same for you. Check out www.zackdesign.biz

== Upgrade Notice ==

Please make sure you are not running Wordpress < 3.0

== Changelog ==

= 1.1 =

- Tested in WP 3.3.2 
- Link update
- Removed the old stylesheet and used the google one for jquery ui

= 1.0 =

- First Release
