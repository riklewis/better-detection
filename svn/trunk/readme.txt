=== Better Detection ===
Contributors: bettersecurity, riklewis
Tags: better, better, security, detection, content, scanner
Requires at least: 3.5
Tested up to: 5.2
Stable tag: trunk
Requires PHP: 5.6
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Improve the security of your website by detecting unexpected changes to content

== Description ==

This plugin will create and store hashes of content (eg. posts, pages, etc.) and monitor these moving forwards in order to detect when changes occur.  When changes are made outside of the normal working process, such as a direct database update, this will then be detected as the hash will get out of sync with the content.
