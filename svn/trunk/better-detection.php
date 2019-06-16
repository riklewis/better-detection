<?php
/*
Plugin Name:  Better Detection
Description:  Improve the security of your website by detecting unexpected changes to both content and files
Version:      0.5
Author:       Better Security
Author URI:   https://bettersecurity.co
License:      GPL3
License URI:  https://www.gnu.org/licenses/gpl-3.0.en.html
Text Domain:  better-detect-text
Domain Path:  /languages
*/

//prevent direct access
defined('ABSPATH') or die('Forbidden');

/*
--------------------------- Installation ---------------------------
*/

define('BETTER_DETECT_VERSION','0.5');

function better_detect_activation() {
	global $wpdb;

	//create table to store post/page hashes
	$table = $wpdb->prefix . "better_detection_hashes";
	$sql = "CREATE TABLE $table (
    hash_id int(10) unsigned NOT NULL AUTO_INCREMENT,
    post_id bigint(20) unsigned,
		filename varchar(255),
		hash_value varchar(255) NOT NULL,
		hash_type varchar(20) NOT NULL,
		hash_date datetime NOT NULL,
	  PRIMARY KEY  (hash_id)
	)";
	better_detect_database($table, $sql);

	//create table to store errors
	$table = $wpdb->prefix . "better_detection_errors";
	$sql = "CREATE TABLE $table (
    error_id int(10) unsigned NOT NULL AUTO_INCREMENT,
		post_id bigint(20) unsigned,
		filename varchar(255),
		old_hash varchar(255) NOT NULL,
		new_hash varchar(255) NOT NULL,
		error_date datetime NOT NULL,
		fixed_date datetime,
	  PRIMARY KEY  (error_id)
	)";
	better_detect_database($table, $sql);

	//store latest version number
	update_option('better_detect_version',BETTER_DETECT_VERSION);

	//create scheduled task
	if(!wp_next_scheduled('better_detection_hourly')) {
	  wp_schedule_event(time(), 'hourly', 'better_detection_hourly');
	}
}
register_activation_hook(__FILE__, 'better_detect_activation');

function better_detect_database($table, $sql) {
	global $wpdb;

  //check if table needs creating/updating
	if($wpdb->get_var("SHOW TABLES LIKE '$table'") !== $table) {
		$create = true;
		$update = false;
	}
	else {
		$dat_ver = get_option('better_detect_version') * 1;
		$cur_ver = BETTER_DETECT_VERSION * 1;
		$create = false;
		$update = ($cur_ver > $dat_ver);
	}

	//table needs creating or updating
	if($create || $update) {
		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta($sql . " " . $wpdb->get_charset_collate());
		return true;
	}

	return false;
}

/*
-------------------------- Uninstallation ---------------------------
*/

function better_detect_deactivation() {
   //cancel scheduled tasks
	 $timestamp = wp_next_scheduled('better_detection_hourly');
   wp_unschedule_event($timestamp, 'better_detection_hourly');
}
register_deactivation_hook(__FILE__, 'better_detect_deactivation');

/*
---------------------------- Detection -----------------------------
*/

//scheduled task execution
function better_detection_do_hourly() {
	global $wpdb;
	$hashes = $wpdb->prefix . "better_detection_hashes";
	$errors = $wpdb->prefix . "better_detection_errors";

	//update options
	update_option('better_detect_running','Y');
	update_option('better_detect_runtime',date("Y-m-d H:i:s"));

	//get posts to check
	$sql = "SELECT * FROM $wpdb->posts WHERE post_status IN ('draft','publish','future') ORDER BY RAND()";
  $rows = $wpdb->get_results($sql);
	foreach($rows as $row) {
    $post_id = $row->ID;
		$content = $row->post_content;
    $newhash = hash("sha256",$content);

		//check if has exists
		$sql = "SELECT * FROM $hashes WHERE post_id = $post_id";
    $rowhash = $wpdb->get_row($sql);
		if($rowhash!==null) {
			//check if hash has changed
			$oldhash = $rowhash->hash_value;
      if($oldhash!==$newhash) {
				//save new hash value
				$wpdb->replace($hashes,
					array(
						'hash_id' => $rowhash->hash_id,
						'post_id' => $post_id,
						'hash_value' => $newhash,
						'hash_type' => 'sha256',
						'hash_date' => date("Y-m-d H:i:s")
					)
				);

				//save hash error
				$wpdb->insert($errors,
					array(
						'post_id' => $post_id,
						'old_hash' => $oldhash,
						'new_hash' => $newhash,
						'error_date' => date("Y-m-d H:i:s")
					)
				);

				//send notifications
				better_detect_do_notify('post',$post_id);
			}
		}
		else {
      //save new hash value
			$wpdb->insert($hashes,
				array(
					'post_id' => $post_id,
					'filename' => '',
					'hash_value' => $newhash,
					'hash_type' => 'sha256',
					'hash_date' => date("Y-m-d H:i:s")
				)
			);
		}
	}

	//update options
	update_option('better_detect_running','N');
	update_option('better_detect_endtime',date("Y-m-d H:i:s"));
}
add_action( 'better_detection_hourly', 'better_detection_do_hourly' );

function better_detect_log($message) {
  if (WP_DEBUG === true) {
    if (is_array($message) || is_object($message)) {
      error_log(print_r($message, true));
    }
		else {
      error_log($message);
    }
  }
}

/*
----------------------------- Settings ------------------------------
*/

//add settings page
function better_detect_menus() {
	add_options_page(__('Better Detection','better-detect-text'), __('Better Detection','better-detect-text'), 'manage_options', 'better-detection-settings', 'better_detect_show_settings');
}

//add the settings
function better_detect_settings() {
	register_setting('better-detection','better-detection-settings');

  add_settings_section('better-detection-section-notify', __('Notifications', 'better-detect-text'), 'better_detect_section_notify', 'better-detection');
  add_settings_field('better-detection-notify-email', __('Email Address', 'better-detect-text'), 'better_detect_notify_email', 'better-detection', 'better-detection-section-notify');
  add_settings_field('better-detection-notify-slack', __('Slack WebHook URL', 'better-detect-text'), 'better_detect_notify_slack', 'better-detection', 'better-detection-section-notify');
}

//allow the settings to be stored
add_filter('whitelist_options', function($whitelist_options) {
  $whitelist_options['better-detection'][] = 'better-detection-notify-email';
  $whitelist_options['better-detection'][] = 'better-detection-notify-slack';
  //todo
  return $whitelist_options;
});

//define output for settings page
function better_detect_show_settings() {
  echo '<div class="wrap">';
  echo '  <div style="padding:12px;background-color:white;margin:24px 0;">';
  echo '    <a href="https://bettersecurity.co" target="_blank" style="display:inline-block;width:100%;">';
  echo '      <img src="' . WP_PLUGIN_URL . '/better-detection/header.png" style="height:64px;">';
  echo '    </a>';
  echo '  </div>';
	echo '  <div style="margin:0 0 24px 0;">';
  echo '    <a href="https://www.php.net/supported-versions.php" target="_blank"><img src="' . better_detect_badge_php() . '"></a>';
  echo '  </div>';
  echo '  <h1>' . __('Better Detection', 'better-detect-text') . '</h1>';
	echo '  <p>This plugin will create and store hashes of content and critical files, and monitor these moving forwards in order to detect when changes occur.  When changes are made outside of the normal working process, such as a direct database update, this will then be detected as the hash will get out of sync with the content.';
  echo '  <form action="options.php" method="post">';

	settings_fields('better-detection');
  do_settings_sections('better-detection');
	submit_button();

  echo '  </form>';
  echo '    </tbody>';
  echo '  </table>';
  echo '</div>';
}

function better_detect_badge_php() {
  $ver = phpversion();
  $col = "critical";
  if(version_compare($ver,'7.1','>=')) {
    $col = "important";
  }
  if(version_compare($ver,'7.2','>=')) {
    $col = "success";
  }
  return 'https://img.shields.io/badge/PHP-' . $ver . '-' . $col . '.svg?logo=php&style=for-the-badge';
}

//define output for settings section
function better_detect_section_notify() {
  echo '<hr>';
}

//defined output for settings
function better_detect_notify_email() {
	$settings = get_option('better-detection-settings');
	$value = "";
	if(isset($settings['better-detection-notify-email']) && $settings['better-detection-notify-email']!=="") {
		$value = $settings['better-detection-notify-email'];
	}
  echo '<input id="better-detection" name="better-detection-settings[better-detection-notify-email]" type="email" size="50" value="' . str_replace('"', '&quot;', $value) . '">';
}

function better_detect_notify_slack() {
	$settings = get_option('better-detection-settings');
	$value = "";
	if(isset($settings['better-detection-notify-slack']) && $settings['better-detection-notify-slack']!=="") {
		$value = $settings['better-detection-notify-slack'];
	}
  echo '<input id="better-detection" name="better-detection-settings[better-detection-notify-slack]" type="url" size="50" value="' . str_replace('"', '&quot;', $value) . '">';
	echo '<br><small><em>See Slack\'s <a href="https://slack.com/services/new/incoming-webhook">Channel Settings &gt; Add an App &gt; Incoming WebHooks</a> menu.</em></small>';
}

function better_detect_do_notify($type,$item_id) {
	$settings = get_option('better-detection-settings');
	$value = "";

	//calculate site domain
	$link = rtrim(home_url('/','https'),'/');
	$home = $link;
	if(strpos($link,'https://')===0) {
		$link = substr($link,8);
	}
	if(strpos($link,'http://')===0) {
		$link = substr($link,7);
	}
	if(strpos($link,'www.')===0) {
		$link = substr($link,4);
	}
	$frmt = get_option('time_format') . ' ' . get_option('date_format');

	//check for email address
	if(isset($settings['better-detection-notify-email']) && $settings['better-detection-notify-email']!=="") {
		$value = $settings['better-detection-notify-email'];
		if($value!=="") {

      //create email body
			$body  = '  <div style="background-color:white;margin:24px 0;">';
			$body .= '    <a href="https://bettersecurity.co" target="_blank" style="display:inline-block;width:100%;">';
			$body .= '      <img src="' . WP_PLUGIN_URL . '/better-detection/header.png" style="height:64px;">';
			$body .= '    </a>';
			$body .= '  </div>';
			$body .= '  <p>You have the <strong>Better Detection</strong> plugin installed on your Wordpress site and it has detected that a change was made outside of the normal working process, such as a direct database update.  The details of the change are below:</p>';
			$body .= '  <p><ul>';
			switch($type) {
				case "post":
					$item = get_post($item_id);
					$body .= '  <li>Type: <strong>' . ucwords($item->post_type) . '</strong></li>';
					$body .= '  <li>Title: <strong><a href="' . get_permalink($item_id) . '">' . $item->post_title . '</a></strong></li>';
					$body .= '  <li>ID: <strong>' . $item->ID . '</strong></li>';
					$body .= '  <li>Status: <strong>' . ucwords($item->post_status) . '</strong></li>';
					$body .= '  <li>Post Date: <strong>' . date($frmt, strtotime($item->post_date)) . '</strong></li>';
					$body .= '  <li>Last Modified: <strong>' . date($frmt, strtotime($item->post_modified)) . '</strong></li>';
					break;
				default:
					$body .= '  <li>Unknown type: <strong>' . $type . '</strong> (ID: ' . $item_id . ')</li>';
			}
			$body .= '  </ul></p>';
			$body .= '  <p>If you recognise this change as one that you made then please ignore this email.  However, you may want to investigate to be sure that you are happy with the change that has been made.</p>';
			$body .= '  <p>We just want to take this opportunity to thank you for using this plugin and we hope that you find it useful.</p>';
			$body .= '  <p>All the best, the <strong>Better Security</strong> team</p>';

      //send HTML email
			add_filter('wp_mail_content_type','better_detect_set_html_mail_content_type');
			wp_mail($value,"ALERT from Better Detection - $link",$body);
			remove_filter('wp_mail_content_type','better_detect_set_html_mail_content_type');
		}
	}

	//check for Slack webhook
	if(isset($settings['better-detection-notify-slack']) && $settings['better-detection-notify-slack']!=="") {
		$value = $settings['better-detection-notify-slack'];
		if($value!=="") {

			//create message text
			switch($type) {
				case "post":
					$item = get_post($item_id);
				  $text = $item->post_type . ' <' . get_permalink($item_id) . '|' . $item->post_title . '>.';
					$text .= ' ID: ' . $item->ID . ', status: ' . $item->post_status . ', post date: ' . date($frmt, strtotime($item->post_date)) . ', last modified: ' . date($frmt, strtotime($item->post_modified)) . '.';
					break;
				default:
          $text = $type . ', ID: ' . $item_id . '.';
			}

			//post message to Slack
      wp_remote_post($value,array(
				'blocking' => false,
				'body' => json_encode(array(
					'text' => 'ALERT from <' . $home . '|' . $link . '> - change detected to ' . $text . '  If this is not expected, please investigate.',
					'username' => 'Better Detection',
					'icon_url' => 'https://bettersecurity.co/images/icon-48x48.png'
				))
			));
		}
	}
}

function better_detect_set_html_mail_content_type() {
	return 'text/html';
}

//add actions
if(is_admin()) {
  add_action('admin_menu','better_detect_menus');
  add_action('admin_init','better_detect_settings');
}

/*
--------------------- Add links to plugins page ---------------------
*/

//show settings link
function better_detect_links($links) {
	$links[] = sprintf('<a href="%s">%s</a>',admin_url('options-general.php?page=better-detection-settings'),'Settings');
	return $links;
}

//add actions
if(is_admin()) {
  add_filter('plugin_action_links_'.plugin_basename(__FILE__),'better_detect_links');
}

/*
----------------------------- The End ------------------------------
*/
