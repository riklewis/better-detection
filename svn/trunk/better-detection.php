<?php
/*
Plugin Name:  Better Detection
Description:  Improve the security of your website by detecting unexpected changes to content
Version:      1.4
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

define('BETTER_DETECTION_VERSION','1.4');

function better_detection_activation() {
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
	better_detection_database($table, $sql);

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
		fixed_mode varchar(10),
	  PRIMARY KEY  (error_id)
	)";
	better_detection_database($table, $sql);

	//store latest version number
	update_option('better_detection_version',BETTER_DETECTION_VERSION);

	//create scheduled task
	if(!wp_next_scheduled('better_detection_hourly')) {
	  wp_schedule_event(time(), 'hourly', 'better_detection_hourly');
	}
}
register_activation_hook(__FILE__, 'better_detection_activation');

function better_detection_database($table, $sql) {
	global $wpdb;

  //check if table needs creating/updating
	if($wpdb->get_var("SHOW TABLES LIKE '$table'") !== $table) {
		$create = true;
		$update = false;
	}
	else {
		$dat_ver = get_option('better_detection_version') * 1;
		$cur_ver = BETTER_DETECTION_VERSION * 1;
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

function better_detection_deactivation() {
   //cancel scheduled tasks
	 $timestamp = wp_next_scheduled('better_detection_hourly');
   wp_unschedule_event($timestamp, 'better_detection_hourly');
}
register_deactivation_hook(__FILE__, 'better_detection_deactivation');

/*
---------------------------- Detection -----------------------------
*/

//scheduled task execution
function better_detection_do_hourly() {
	global $wpdb;

	//update options
	update_option('better_detection_running','Y');
	update_option('better_detection_runtime',date("Y-m-d H:i:s"));

	//get posts to check
	$sql = "SELECT * FROM $wpdb->posts WHERE post_status IN ('draft','publish','future')";
  $rows = $wpdb->get_results($sql);
	foreach($rows as $row) {
    better_detection_do_post($row,true);
	}

	//update options
	update_option('better_detection_running','N');
	update_option('better_detection_endtime',date("Y-m-d H:i:s"));
}
add_action('better_detection_hourly', 'better_detection_do_hourly');

//process a post
function better_detection_do_post($item,$boo) {
	global $wpdb;
	$hashes = $wpdb->prefix . "better_detection_hashes";
	$errors = $wpdb->prefix . "better_detection_errors";

  //get post content and calculate hash
	$post_id = $item->ID;
	$content = $item->post_content;
	$newhash = hash("sha256",$content);

	//check if hash exists for this post
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

      if($boo) {
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
				better_detection_do_notify('post',$post_id);
			}
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

function better_detection_do_notify($type,$item_id) {
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
	$frmt = get_option('time_format') . ', ' . get_option('date_format');

	//create and store unique
	$guid = "";
	$auto = "";
	if(isset($settings['better-detection-notify-login']) && $settings['better-detection-notify-login']!=="") {
		$login = $settings['better-detection-notify-login'];
		if($login!=="") {
			$used = false;
			$guid = better_detection_guid();
			$auto = $home . '?token=' . $guid;
			set_transient("better_detection_auto_login_" . $guid, $login, DAY_IN_SECONDS);
		}
	}

	//check for email address
	if(isset($settings['better-detection-notify-email']) && $settings['better-detection-notify-email']!=="") {
		$value = $settings['better-detection-notify-email'];
		if($value!=="") {

      //create email body
			$body  = '  <div style="background-color:white;margin:24px 0;">';
			$body .= '    <a href="https://bettersecurity.co" target="_blank" style="display:inline-block;width:100%;">';
			$body .= '      <img src="' . plugins_url('header.png', __FILE__) . '" style="height:64px;">';
			$body .= '    </a>';
			$body .= '  </div>';
			$body .= '  <p>' . __('You have the <strong>Better Detection</strong> plugin installed on your Wordpress site and it has detected that a change was made outside of the normal working process, such as a direct database update.  The details of the change are below:', 'better-detect-text') . '</p>';
			$body .= '  <p><ul>';
			switch($type) {
				case "post":
					$item = get_post($item_id);
					$body .= '  <li>' . __('Type', 'better-detect-text') . ': <strong>' . ucwords($item->post_type) . '</strong></li>';
					$body .= '  <li>' . __('Title', 'better-detect-text') . ': <strong><a href="' . get_permalink($item_id) . '">' . $item->post_title . '</a></strong></li>';
					$body .= '  <li>' . __('ID', 'better-detect-text') . ': <strong>' . $item->ID . '</strong></li>';
					$body .= '  <li>' . __('Status', 'better-detect-text') . ': <strong>' . ucwords($item->post_status) . '</strong></li>';
					$body .= '  <li>' . __('Post Date', 'better-detect-text') . ': <strong>' . date($frmt, strtotime($item->post_date)) . '</strong></li>';
					$body .= '  <li>' . __('Last Modified', 'better-detect-text') . ': <strong>' . date($frmt, strtotime($item->post_modified)) . '</strong></li>';
					break;
				default:
					$body .= '  <li>' . __('Unknown type', 'better-detect-text') . ': <strong>' . $type . '</strong> (' . __('ID', 'better-detect-text') . ': ' . $item_id . ')</li>';
			}
			$body .= '  </ul></p>';
			$body .= '  <p>' . __('If you recognise this change as one that you made then please ignore this email.  However, you may want to investigate to be sure that you are happy with the change that has been made.', 'better-detect-text') . '</p>';
			if($auto!=="") {
			  $body .= '  <p><a href="' . $auto . '">' . __('Click here to automatically log in to the dashboard', 'better-detect-text') . '</a>. <em>' . __('This is a single use link that expires in 24 hours', 'better-detect-text') . '.</em></p>';
				$used = true;
			}
			$body .= '  <p>' . __('We just want to take this opportunity to thank you for using this plugin and we hope that you find it useful.', 'better-detect-text') . '</p>';
			$body .= '  <p>' . __('All the best, the <strong>Better Security</strong> team', 'better-detect-text') . '</p>';

      //send HTML email
			add_filter('wp_mail_content_type','better_detection_set_html_mail_content_type');
			wp_mail($value, __('ALERT from Better Detection', 'better-detect-text') . ' - $link',$body);
			remove_filter('wp_mail_content_type','better_detection_set_html_mail_content_type');
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
				  $text = $item->post_type;
					$flds = array(
						[
							'title' => __('ID', 'better-detect-text'),
							'value' => $item->ID,
							'short' => true
						],
						[
							'title' => __('Post Date', 'better-detect-text'),
							'value' => date($frmt, strtotime($item->post_date)),
							'short' => true
						],
						[
							'title' => __('Status', 'better-detect-text'),
							'value' => ucwords($item->post_status),
							'short' => true
						],
						[
							'title' => __('Last Modified', 'better-detect-text'),
							'value' => date($frmt, strtotime($item->post_modified)),
							'short' => true
						]
					);
					if($auto!=="") {
						$flds[] = [
							'title' => __('Dashboard Link', 'better-detect-text'),
							'value' => '<' . $auto . '|' . __('Click here to automatically log in to the dashboard', 'better-detect-text') . '>',
							'short' => false
						];
					}
					$atts = array([
		        'fallback' => __('ALERT from', 'better-detect-text') . ' <' . $home . '|' . $link . '> - ' . __('change detected to', 'better-detect-text') . ' ' . $item->post_type . ' <' . get_permalink($item_id) . '|' . $item->post_title . '>',
		        'color' => '#000000',
						'title' => $item->post_title,
            'title_link' => get_permalink($item_id),
						'footer' => 'Better Security',
						'footer_icon' => 'https://bettersecurity.co/images/icon-48x48.png',
		        'fields' => $flds
		      ]);
					$used = true;
					break;
				default:
          $text = $type . ' (' . __('ID', 'better-detect-text') . ': ' . $item_id . ')';
					$atts = array();
			}

			//post message to Slack
      wp_remote_post($value,array(
				'blocking' => false,
				'body' => json_encode(array(
					'text' => __('ALERT from', 'better-detect-text') . ' <' . $home . '|' . $link . '> - ' . __('change detected to', 'better-detect-text') . ' ' . $text . '.  ' . __('If this is not expected, please investigate.', 'better-detect-text'),
					'username' => 'Better Detection',
					'icon_url' => 'https://bettersecurity.co/images/icon-48x48.png',
					'attachments' => $atts
				))
			));
		}
	}

	//remove unique ID if not used
	if($guid!=="" && !$used) {
		delete_transient("better_detection_auto_login_" . $guid);
	}
}

function better_detection_do_test($type,$value) {
	$settings = get_option('better-detection-settings');

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
  $frmt = get_option('time_format') . ', ' . get_option('date_format');

	//create and store unique
	$guid = "";
	$auto = "";
	if(isset($settings['better-detection-notify-login']) && $settings['better-detection-notify-login']!=="") {
		$login = $settings['better-detection-notify-login'];
		if($login!=="") {
			$used = false;
			$guid = better_detection_guid();
			$auto = $home . '?token=' . $guid;
			set_transient("better_detection_auto_login_" . $guid, $login, DAY_IN_SECONDS);
		}
	}

	//check for email address
	if($type==="email" && $value!=="") {
    //create email body
		$body  = '  <div style="background-color:white;margin:24px 0;">';
		$body .= '    <a href="https://bettersecurity.co" target="_blank" style="display:inline-block;width:100%;">';
		$body .= '      <img src="' . plugins_url('header.png', __FILE__) . '" style="height:64px;">';
		$body .= '    </a>';
		$body .= '  </div>';
		$body .= '  <p>' . __('You have the <strong>Better Detection</strong> plugin installed on your Wordpress site and this test notification was triggered.  The details of the test are below:', 'better-detect-text') . '</p>';
		$body .= '  <p><ul>';
		$body .= '  <li>' . __('Type', 'better-detect-text') . ': <strong>' . __('Test', 'better-detect-text') . '</strong></li>';
		$body .= '  <li>' . __('Test Date', 'better-detect-text') . ': <strong>' . current_time($frmt) . '</strong></li>';
		$body .= '  </ul></p>';
		if($auto!=="") {
			$body .= '  <p><a href="' . $auto . '">' . __('Click here to automatically log in to the dashboard', 'better-detect-text') . '</a>. <em>' . __('This is a single use link that expires in 24 hours', 'better-detect-text') . '.</em></p>';
			$used = true;
		}
		$body .= '  <p>' . __('We just want to take this opportunity to thank you for using this plugin and we hope that you find it useful.', 'better-detect-text') . '</p>';
		$body .= '  <p>' . __('All the best, the <strong>Better Security</strong> team', 'better-detect-text') . '</p>';

    //send HTML email
		add_filter('wp_mail_content_type','better_detection_set_html_mail_content_type');
		$boo = wp_mail($value, __('ALERT from Better Detection', 'better-detect-text') . ' - ' . $link,$body);
		remove_filter('wp_mail_content_type','better_detection_set_html_mail_content_type');
		return $boo;
	}

	//check for Slack webhook
	if($type==="slack" && $value!=="") {
		//create message attachments
		$flds = array(
			[
				'title' => __('Test Date', 'better-detect-text'),
				'value' => current_time($frmt),
				'short' => true
			]
		);
		if($auto!=="") {
			$flds[] = [
				'title' => __('Dashboard Link', 'better-detect-text'),
				'value' => '<' . $auto . '|' . __('Click here to automatically log in to the dashboard', 'better-detect-text') . '>',
				'short' => false
			];
		}
		$atts = array([
			'fallback' => __('ALERT from', 'better-detect-text') . ' <' . $home . '|' . $link . '> - ' . __('test notification. Has it worked?', 'better-detect-text'),
			'color' => '#000000',
			'footer' => 'Better Security',
			'footer_icon' => 'https://bettersecurity.co/images/icon-48x48.png',
			'fields' => $flds
		]);

		//post message to Slack
	  wp_remote_post($value,array(
			'blocking' => false,
			'body' => json_encode(array(
				'text' => __('ALERT from', 'better-detect-text') . ' <' . $home . '|' . $link . '> - ' . __('test notification. Has it worked?', 'better-detect-text'),
				'username' => 'Better Detection',
				'icon_url' => 'https://bettersecurity.co/images/icon-48x48.png',
				'attachments' => $atts
			))
		));
		return true;
	}

	//remove unique ID if not used
	if($guid!=="" && !$used) {
		delete_transient("better_detection_auto_login_" . $guid);
	}
	return false;
}

//set email as HTML
function better_detection_set_html_mail_content_type() {
	return 'text/html';
}

//store when post is updated/created
function better_detection_save_post($post_id, $post, $update) {
	if(defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
		//process post on auto-save
		better_detection_do_post($post,false);
	}
  else {
		//flag post to be processed later
    set_transient("better_detection_save_post_" . $post_id, ($update ? "UPDATED" : "CREATED"), 30);
	}
}
add_action('save_post', 'better_detection_save_post', 10, 3);

//update when posted in admin only
function better_detection_updated_messages($messages) {
  global $post;
  global $wpdb;
	$errors = $wpdb->prefix . "better_detection_errors";

	//append tagline to all messages
  $type = $post->post_type;
  $mess = " <img src='" . plugins_url('icon-36x36.png', __FILE__) . "' align='top' style='height:18px;margin:0 4px 0 18px;'>" . __('Protected by', 'better-detect-text') . " <strong>Better Detection</stong>";
	for($i=1;$i<11;$i++) {
		$messages[$type][$i] .= $mess;
	}

	//check if post has been saved
	$boo = get_transient("better_detection_save_post_" . $post->ID);
  if($boo!==false) {
	  //process post
		better_detection_do_post($post,false);

		//assume errors have been fixed
		$wpdb->update($errors,
			array(
				'fixed_date' => date("Y-m-d H:i:s"),
				'fixed_mode' => 'saved'
			),
			array(
				'post_id' => $post->ID,
				'fixed_date' => null
			)
		);
	}
	delete_transient("better_detection_save_post_" . $post->ID);

  return $messages;
}
add_filter('post_updated_messages', 'better_detection_updated_messages');


//debug logging if required
function better_detection_log($message) {
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
------------------------- Automatic Login ---------------------------
*/

//create GUID-ish
function better_detection_guid() {
	return rtrim(strtr(base64_encode(rand() . uniqid('',true)), '+/', '-_'), '=');
}

//handle login request
function better_detection_auto_login() {
  if(isset($_GET['token']) && $_GET['token']!=="") {
    $token = $_GET['token'];

		//check token is genuine and hasn't expired
		$login = get_transient("better_detection_auto_login_" . $token);
		if($login!==false && $login!=="") {

			//get user that this token was created for
      $user = get_user_by('id', intval($login));
      if($user) {

				//log that user in
				wp_set_auth_cookie($user->ID, false);
				do_action('wp_login', $user->name, $user);

				//link only works once
				delete_transient("better_detection_auto_login_" . $token);

        //redirect to settings page
				header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
				header("Cache-Control: no-cache, no-store, must-revalidate, private, max-age=0, s-maxage=0");
				header("Cache-Control: post-check=0, pre-check=0", false);
				header("Pragma: no-cache");
				header("Expires: Mon, 01 Jan 1990 01:00:00 GMT");
				wp_redirect(admin_url('options-general.php') . '?page=better-detection-settings');
				exit;
		  }
		}

		//token hasn't worked but just to be safe
		delete_transient("better_detection_auto_login_" . $token);
	}
}
add_action('init', 'better_detection_auto_login');

/*
-------------------------- AJAX Functions ---------------------------
*/

function better_detection_do_ajax() {
	global $wpdb;
	$errors = $wpdb->prefix . "better_detection_errors";

  //check security key
	if(check_ajax_referer('better-detection-nonce', 'key', false)) {
    //check id is populated
		$id = sanitize_text_field($_POST['id']);
		if($id) {
			//check mode
			$mode = sanitize_text_field($_POST['mode']);
	    switch($mode) {
	      case "fixed":
					$res = $wpdb->replace($errors,
						array(
							'error_id' => $id,
							'fixed_date' => date("Y-m-d H:i:s"),
							'fixed_mode' => 'fixed'
						)
					);
					if($res===false) {
						echo "Error: Update failed";
					}
					else {
						echo "Success";
					}
					break;
				case "ignore":
					$res = $wpdb->replace($errors,
						array(
							'error_id' => $id,
							'fixed_date' => date("Y-m-d H:i:s"),
							'fixed_mode' => 'ignore'
						)
					);
					if($res===false) {
						echo "Error: Update failed";
					}
					else {
						echo "Success";
					}
					break;
	      case "test":
				  $val = sanitize_text_field($_POST['val']);
					if($val) {
	          better_detection_do_test($id,$val);
					}
					else {
						echo "Error: Value missing";
					}
	        break;
				default:
				  echo "Error: Invalid mode";
			}
		}
		else {
			echo "Error: ID missing";
		}
  }
	else {
		echo "Error: Key mismatch";
	}

  //return out
	wp_die();
}
add_action('wp_ajax_better_detection', 'better_detection_do_ajax');

/*
----------------------------- Settings ------------------------------
*/

function better_detection_admin_scripts() {
	if(isset($_GET["page"]) && $_GET["page"]==="better-detection-settings") {
	  wp_enqueue_script('jquery-ui-core');
	  wp_enqueue_script('jquery-ui-tabs');

		wp_enqueue_script('better-detection-main-js', plugins_url('main.js', __FILE__),array('jquery','jquery-ui-tabs'),false,true);
		wp_localize_script('better-detection-main-js', 'ajax_object', array(
			'url' => admin_url('admin-ajax.php'),
			'key' => wp_create_nonce('better-detection-nonce'),
			'gif' => plugins_url('working.gif', __FILE__)
		));

		wp_enqueue_style('jquery-ui-tabs-min-css', plugins_url('jquery-ui-tabs.min.css', __FILE__));
	}
}
add_action('admin_enqueue_scripts', 'better_detection_admin_scripts');

//add settings page
function better_detection_menus() {
	add_options_page(__('Better Detection','better-detect-text'), __('Better Detection','better-detect-text'), 'manage_options', 'better-detection-settings', 'better_detection_show_settings');
}

//add the settings
function better_detection_settings() {
	register_setting('better-detection','better-detection-settings');

	add_settings_section('better-detection-section-notify', __('Notifications', 'better-detect-text'), 'better_detection_section_notify', 'better-detection');
  add_settings_field('better-detection-notify-email', __('Email Address', 'better-detect-text'), 'better_detection_notify_email', 'better-detection', 'better-detection-section-notify');
  add_settings_field('better-detection-notify-slack', __('Slack WebHook URL', 'better-detect-text'), 'better_detection_notify_slack', 'better-detection', 'better-detection-section-notify');
  add_settings_field('better-detection-notify-login', __('Automatic Login Link', 'better-detect-text'), 'better_detection_notify_login', 'better-detection', 'better-detection-section-notify');
}

//allow the settings to be stored
add_filter('whitelist_options', function($whitelist_options) {
  $whitelist_options['better-detection'][] = 'better-detection-notify-email';
  $whitelist_options['better-detection'][] = 'better-detection-notify-slack';
  $whitelist_options['better-detection'][] = 'better-detection-notify-login';
  return $whitelist_options;
});

//define output for settings page
function better_detection_show_settings() {
	global $wpdb;
	$errors = $wpdb->prefix . "better_detection_errors";
	$frmt = get_option('time_format') . ', ' . get_option('date_format');

  echo '<div class="wrap">';
  echo '  <div style="padding:12px;background-color:white;margin:24px 0;">';
  echo '    <a href="https://bettersecurity.co" target="_blank" style="display:inline-block;width:100%;">';
  echo '      <img src="' . plugins_url('header.png', __FILE__) . '" style="height:64px;">';
  echo '    </a>';
  echo '  </div>';
	echo '  <div style="margin:0 0 24px 0;">';
  echo '    <a href="https://www.php.net/supported-versions.php" target="_blank"><img src="' . better_detection_badge_php() . '"></a>';
  echo '  </div>';
  echo '  <h1>' . __('Better Detection', 'better-detect-text') . '</h1>';
	echo '  <p>' . __('This plugin will create and store hashes of content (eg. posts, pages, etc.) and monitor these moving forwards in order to detect when changes occur.  When changes are made outside of the normal working process, such as a direct database update, this will then be detected as the hash will get out of sync with the content.', 'better-detect-text');
  echo '  <div id="better-detection-tabs">';
  echo '    <ul>';
  echo '      <li><a href="#better-detection-tabs-errors">' . __('Errors', 'better-detect-text') . '<span id="better-detection-error-count"></span></a></li>';
  echo '      <li><a href="#better-detection-tabs-settings">' . __('Settings', 'better-detect-text') . '</a></li>';
  //echo '      <li><a href="#better-detection-tabs-extras">Extras</a></li>';
  echo '    </ul>';
  echo '    <div id="better-detection-tabs-errors">';

	//check if unfixed errors
	$count = $wpdb->get_var("SELECT COUNT(*) FROM $errors WHERE fixed_date IS NULL");
	if($count>0) {
		echo '    	<table class="wp-list-table widefat striped">';
		echo '      	<thead>';
		echo '        	<tr>';
		echo '    		    <th scope="col" id="better-detection-type" class="manage-column column-name column-primary">' . __('Type', 'better-detect-text') . '</th>';
		echo '            <th scope="col" id="better-detection-desc" class="manage-column column-description">' . __('Title', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" id="better-detection-indx" class="manage-column column-index">' . __('ID', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" id="better-detection-stat" class="manage-column column-status">' . __('Status', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" id="better-detection-cred" class="manage-column column-datetime">' . __('Created', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" id="better-detection-modd" class="manage-column column-datetime">' . __('Modified', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" id="better-detection-detd" class="manage-column column-datetime">' . __('Change Detected', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" id="better-detection-actn" class="manage-column column-actions">' . __('Action', 'better-detect-text') . '</th>';
		echo '         </tr>';
		echo '      	</thead>';
	  echo '        <tbody id="better-detection-list">';
		$sql = "SELECT * FROM $errors WHERE fixed_date IS NULL ORDER BY error_date ASC";
		$rows = $wpdb->get_results($sql);
		foreach($rows as $row) {
			if($row->post_id) {
				$item = get_post($row->post_id);
				$type = __(ucwords($item->post_type), 'better-detect-text');
				$desc = '<a href="' . get_permalink($item->ID) . '" target="blank">' . $item->post_title . ' <span class="dashicons dashicons-external"></span></a>';
				$indx = $item->ID;
				$stat = ucwords($item->post_status);
				$cred = date($frmt, strtotime($item->post_date));
				$modd = date($frmt, strtotime($item->post_modified));
			}
			else {
				$type = __('File', 'better-detect-text');
				$desc = $row->filename;
				$indx = "";
				$stat = ""; //added/updated/deleted?
				$cred = ""; //file created date
				$modd = ""; //file modified date
			}
			echo '    		  <tr class="inactive">';
			echo '            <td class="column-primary">' . $type . '</td>';
			echo '            <td class="column-description desc">' . $desc . '</td>';
			echo '            <td class="column-index">' . $indx . '</td>';
			echo '            <td class="column-status">' . $stat . '</td>';
			echo '            <td class="column-datetime">' . $cred . '</td>';
			echo '            <td class="column-datetime">' . $modd . '</td>';
			echo '            <td class="column-datetime">' . date($frmt, strtotime($row->error_date)) . '</td>';
			echo '            <td class="column-actions">';
			echo '              <input type="button" id="action-fix-' . $row->error_id . '" class="button button-primary action-fixed" value="' . __('Fixed', 'better-detect-text') . '">';
			echo '              <input type="button" id="action-ign-' . $row->error_id . '" class="button button-secondary action-ignore" value="' . __('Ignore', 'better-detect-text') . '">';
			echo '            </td>';
			echo '          </tr>';
		}
		echo '        </tbody>';
		echo '      	<tfoot>';
		echo '        	<tr>';
		echo '    		    <th scope="col" class="manage-column column-name column-primary">' . __('Type', 'better-detect-text') . '</th>';
		echo '            <th scope="col" class="manage-column column-description">' . __('Title', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" class="manage-column column-index">' . __('ID', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" class="manage-column column-status">' . __('Status', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" class="manage-column column-datetime">' . __('Created', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" class="manage-column column-datetime">' . __('Modified', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" class="manage-column column-datetime">' . __('Change Detected', 'better-detect-text') . '</th>';
		echo '    		    <th scope="col" class="manage-column column-actions">' . __('Action', 'better-detect-text') . '</th>';
		echo '         </tr>';
		echo '        </tfoot>';
		echo '      </table>';
	}
	else {
		echo '      <p>' . __('No new errors have been detected - yay!', 'better-detect-text') . '</p>';
	}
	echo '    </div>';
	echo '    <div id="better-detection-tabs-settings">';
	echo '      <form action="options.php" method="post">';
	settings_fields('better-detection');
  do_settings_sections('better-detection');
	submit_button();
  echo '      </form>';
	echo '    </div>';
	//echo '    <div id="better-detection-tabs-extras">';
	//echo '    </div>';
	echo '  </div>';
  echo '</div>';
}

function better_detection_badge_php() {
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
function better_detection_section_notify() {
  echo '<hr>';
}

//defined output for settings
function better_detection_notify_email() {
	$settings = get_option('better-detection-settings');
	$value = "";
	if(isset($settings['better-detection-notify-email']) && $settings['better-detection-notify-email']!=="") {
		$value = $settings['better-detection-notify-email'];
	}
  echo '<input id="better-detection-notify-email" name="better-detection-settings[better-detection-notify-email]" type="email" size="50" value="' . str_replace('"', '&quot;', $value) . '"> <input type="button" id="action-tst-email" class="button button-secondary action-test" value="' . __('Send test', 'better-detect-text') . '">';
}

function better_detection_notify_slack() {
	$settings = get_option('better-detection-settings');
	$value = "";
	if(isset($settings['better-detection-notify-slack']) && $settings['better-detection-notify-slack']!=="") {
		$value = $settings['better-detection-notify-slack'];
	}
	echo '<input id="better-detection-notify-slack" name="better-detection-settings[better-detection-notify-slack]" type="url" size="50" value="' . str_replace('"', '&quot;', $value) . '"> <input type="button" id="action-tst-slack" class="button button-secondary action-test" value="' . __('Send test', 'better-detect-text') . '">';
	echo '<br><small><em>&nbsp;' . __('See Slack\'s', 'better-detect-text') . ' <a href="https://slack.com/services/new/incoming-webhook">' . __('Channel Settings > Add an App > Incoming WebHooks', 'better-detect-text') . '</a> ' . __('menu.', 'better-detect-text') . '</em></small>';
}

function better_detection_notify_login() {
	$settings = get_option('better-detection-settings');
	$value = "";
	if(isset($settings['better-detection-notify-login']) && $settings['better-detection-notify-login']!=="") {
		$value = $settings['better-detection-notify-login'];
	}
	echo '<select id="better-detection-notify-login" name="better-detection-settings[better-detection-notify-login]">';
	echo better_detection_login_option('',$value,'-- ' . __('Do not include a login link', 'better-detect-text') . ' -- ');
	$users = get_users();
  foreach($users as $user) {
		$meta = get_user_meta($user->ID);
		echo better_detection_login_option(strval($user->ID), $value, __('Log in as', 'better-detect-text') . ': ' . $user->user_login);
  }
	echo '</select>';
	echo '<br><small><em>&nbsp;' . __('Please note that no password will be required so keep these links private.', 'better-detect-text') . '</em></small>';
}

function better_detection_login_option($opt,$val,$txt) {
  return '  <option value="' . $opt . '"' . ($opt===$val ? ' selected' : '') . '>' . $txt . '</option>';
}

//add actions
if(is_admin()) {
  add_action('admin_menu','better_detection_menus');
  add_action('admin_init','better_detection_settings');
}

/*
----------------------- Add link to admin bar ----------------------
*/

//add link to the admin bar
function better_detection_admin_bar_render() {
	global $wp_admin_bar;
	global $wpdb;
	$errors = $wpdb->prefix . "better_detection_errors";

	//check if unfixed errors
	$count = $wpdb->get_var("SELECT COUNT(*) FROM $errors WHERE fixed_date IS NULL");
	if($count>0) {
		$wp_admin_bar->add_menu(array(
			'parent' => false,
			'id' => 'better-detection',
			'title' => "<img src='" . plugins_url('icon-white-36x36.png', __FILE__) . "' align='top' style='height:18px;margin:0 4px 0 0;position:relative;top:6px;'>Better Detection ($count)",
			'href' => admin_url('options-general.php') . '?page=better-detection-settings',
			'meta' => false
		));
	}
}
add_action('wp_before_admin_bar_render', 'better_detection_admin_bar_render');

/*
--------------------- Add links to plugins page ---------------------
*/

//show settings link
function better_detection_links($links) {
	$links[] = sprintf('<a href="%s">%s</a>',admin_url('options-general.php?page=better-detection-settings'), __('Settings', 'better-detect-text'));
	return $links;
}

//show Pro link
function better_detection_meta($links, $file) {
	if($file===plugin_basename(__FILE__)) {
		$links[] = '<a href="plugin-install.php?tab=plugin-information&plugin=better-security-pro&TB_iframe=true&width=600&height=550"><em><strong>' . __('Check out Better Security Pro', 'better-detect-text') . '</strong></em></a>';
	}
	return $links;
}

//add actions
if(is_admin()) {
  add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'better_detection_links');
	add_filter('plugin_row_meta', 'better_detection_meta', 10, 2);
}

/*
----------------------------- The End ------------------------------
*/
