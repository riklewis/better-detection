<?php
/*
Plugin Name:  Better Detection
Description:  Improve the security of your website by detecting unexpected changes to both content and files
Version:      1.0
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
---------------------------- Detection -----------------------------
*/



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
