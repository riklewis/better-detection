<?php
/*
Plugin Name:  Better Detection
Description:  Improve the security of your website by detecting unexpected changes to both content and files
Version:      0.4
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

define('BETTER_DETECT_VERSION','0.4');

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
		old_hash int(10) unsigned NOT NULL,
		new_hash int(10) unsigned NOT NULL,
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
  $rows = $wpdb->get_results("SELECT * FROM $wpdb->posts WHERE post_status IN ('draft','publish','future') ORDER BY RAND()" . (DISABLE_WP_CRON ? "" : " LIMIT 50"));
	foreach($rows as $row) {
    $post_id = $row->ID;
		$content = $row->post_content;
    $newhash = hash("sha256",$content);

		//check if has exists
    $rowhash = $wpdb->get_row("SELECT * FROM $hashes WHERE post_id = $post_id" );
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

				//send notification
				//todo
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

/*
----------------------------- Settings ------------------------------
*

//add settings page
function better_detect_menus() {
	add_options_page(__('Better Detection','better-detect-text'), __('Better Detection','better-detect-text'), 'manage_options', 'better-detection-settings', 'better_detect_show_settings');
}

//add the settings
function better_detect_settings() {
	register_setting('better-detection','better-detection-settings');

  add_settings_section('better-detection-section-rp', __('Referrer Policy', 'better-detect-text'), 'better_detect_section_rp', 'better-detection');
  add_settings_field('better-detection-rp', __('Referrer Policy', 'better-detect-text'), 'better_detect_rp', 'better-detection', 'better-detection-section-rp');

  //todo
}

//allow the settings to be stored
add_filter('whitelist_options', function($whitelist_options) {
  $whitelist_options['better-detection'][] = 'better-detection-rp';
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
  echo '    <a href="https://www.php.net/supported-versions.php" target="_blank"><img src="' . better_pass_badge_php() . '"></a>';
  echo '  </div>';
  echo '  <h1>' . __('Better Detection', 'better-detect-text') . '</h1>';
  echo '  <form action="options.php" method="post">';

	settings_fields('better-detection');
  do_settings_sections('better-detection');
	submit_button();

  echo '  </form>';
  echo '    </tbody>';
  echo '  </table>';
  echo '</div>';
}

function better_pass_badge_php() {
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
function better_detect_section_rp() {
  echo '<hr>';
}

//defined output for settings
function better_detect_rp() {
	$settings = get_option('better-detection-settings');
	$value = ($settings['better-detection-rp'] ?: "");
  //todo
}

//add actions
if(is_admin()) {
  add_action('admin_menu','better_detect_menus');
  add_action('admin_init','better_detect_settings');
}

/*
--------------------- Add links to plugins page ---------------------
*

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
