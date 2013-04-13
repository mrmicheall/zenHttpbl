<?php
/*
Zenphoto plug-in implementation of Project HoneyPot's HTTP Blacklist service.
zenHttpbl utilizes Project Honey Pot's HTTP:BL service to stop spammers, harvesters,
and comment spammers in their tracks.  By utilizing the HTTP:BL API and making a DNS
query to the PHP servers you are given information categorizing an IP from tracking
records, identifying if that IP has been part of any suspicious or malicious activity.

This implementation does all this before serving any web pages, and then (if the visitor
passes the thresholds you set via options) either redirects to a honey pot, or serves a
blank page.  Saving you traffic, and dramatically reducing annoying comment/content spammers.

As an added feature, if you specify a honey pot link or Project Honey Pot QuickLink, the 
plugin will add invisible links to your honey pot in an effort to help maintain and keep the
HTTP:BL service up-to-date.

Author - Micheal Luttrull (micheall)
*/
$plugin_is_filter = 5|THEME_PLUGIN;
$plugin_description = gettext_pl("This plug-in utilizes Project HoneyPot's HTTP:BL service to blacklist known spammers/harvesters/comment spammers and block their access to your site.");
$plugin_author      = gettext_pl("Micheal Luttrull (micheall).");
$plugin_version     = "1.4.4.4";
$plugin_URL         = "http://inthemdl.net/pages/zenhttpbl";

/*
Plugin options.
*/
$option_interface   = 'zenHttpblOptions';
/*

Register HTTP:BL filter and Honey Pot Links if enabled.
*/
zp_register_filter('theme_head', 'zenHttpbl');
zp_register_filter('theme_body_open', 'zenHoneyPotLinks');
zp_register_filter('theme_body_close', 'zenHoneyPotLinks');

/*
Plugin option handling class
*/
class zenHttpblOptions {
				function zenHttpblOptions() {
								setOptionDefault('zenHttpbl_enabled', 0);
								setOptionDefault('zenHttpbl_apikey', NULL);
								setOptionDefault('zenHttpbl_ageofthreat', 30);
								setOptionDefault('zenHttpbl_threatrating', 25);
								setOptionDefault('zenHttpbl_honeypotlink', NULL);
								setOptionDefault('zenHttpbl_honeypotquicklink', NULL);
								setOptionDefault('zenHttpbl_eventcount', NULL);
								setOptionDefault('zenHttpbl_badevents', 0);
								setOptionDefault('zenHttpbl_enabletest', NULL);
								setOptionDefault('zenHttpbl_manualtestip', NULL);
				}
				
				function getOptionsSupported() {
								return array(
												gettext_pl('Enable HTTP:BL?') => array(
																'key' => 'zenHttpbl_enabled',
																'type' => OPTION_TYPE_CHECKBOX,
																'order' => 0,
																'desc' => gettext_pl('Do you want to enable the Project HoneyPot HTTP:BL blacklist? <em>Note: This will be ignored if you have not specified your API KEY</em>')
												),
												gettext_pl('API Key') => array(
																'key' => 'zenHttpbl_apikey',
																'type' => 0,
																'order' => 1,
																'desc' => gettext_pl('Enter your Project HoneyPot HTTP:BL API Key you obtained by signing up <a href="http://www.projecthoneypot.org/home.php" target="_blank">here</a>.')
												),
												gettext_pl('Days since last bad event?') => array(
																'key' => 'zenHttpbl_ageofthreat',
																'type' => 0,
																'order' => 2,
																'desc' => gettext_pl('Specify the number of days to since last bad event before considering visitor to be safe.')
												),
												gettext_pl('Maximum allowable threat rating?') => array(
																'key' => 'zenHttpbl_threatrating',
																'type' => 0,
																'order' => 3,
																'desc' => gettext_pl('Enter allowable threat rating before being blocked: 0 (no threat) - 255 (maximum threat)  For more information visit <a href="http://www.projecthoneypot.org/threat_info.php" target="_blank">here</a>.')
												),
												gettext_pl('Your Honey Pot Link?') => array(
																'key' => 'zenHttpbl_honeypotlink',
																'type' => 0,
																'order' => 5,
																'desc' => gettext_pl('If you have enabled a honeypot, enter your HoneyPot here to redirect harmful visitors to. For more information visit <a href="http://www.projecthoneypot.org/?rf=90351" target="_blank">here</a>.')
												),
												gettext_pl('Project Honey Pot Quick Link?') => array(
																'key' => 'zenHttpbl_honeypotquicklink',
																'type' => 0,
																'order' => 6,
																'desc' => gettext_pl('If you want to add a Project Honey Pot QuickLink, enter it here to redirect harmful visitors. For more information visit <a href="http://www.projecthoneypot.org/?rf=90351" target="_blank">here</a>.')
												),
												gettext_pl('Test with a manual IP?') => array(
																'key' => 'zenHttpbl_enabletest',
																'type' => OPTION_TYPE_CHECKBOX,
																'order' => 7,
																'desc' => gettext_pl('This enables testing of zenHttpbl with a manul IP entry.')
												),
												gettext_pl('Enter test IP here.') => array(
																'key' => 'zenHttpbl_manualtestip',
																'type' => 0,
																'order' => 8,
																'desc' => gettext_pl('Want to test with a specific IP?  Enter it here.')
												),
												gettext_pl('Track # of bad events blocked?') => array(
																'key' => 'zenHttpbl_eventcount',
																'type' => OPTION_TYPE_CHECKBOX,
																'order' => 9,
																'desc' => gettext_pl('This enables tracking the # of bad events blocked.<br /><b>Currently # of blocked bad events: <em>' . getOption('zenHttpbl_badevents') . '</em></b><br />')
												)
								);
				}
				
				function handleOption($option, $currentValue) {
				}
}

/*
Process HTTP:BL request
*/
function zenHttpbl() {
				// Get/Set variable defaults
				$enabled      = getOption('zenHttpbl_enabled');
				$apikey       = getOption('zenHttpbl_apikey');
				$hp           = getOption('zenHttpbl_honeypotlink');
				$ql			  = getOption('zenHttpbl_honeypotquicklink');
				$blresult     = NULL;
				$resolved     = false;
				$ageofthreat  = false;
				$threatrating = false;
				if (($enabled != 1) || ($enabled == NULL) || ($apikey == NULL) || ($apikey == '')) {
								//Meta Key for debug, disabled HTTPBL if turned off, or no API key.
								//echo '<meta property="httpbl" content="disabled" />';
				} else {
								//Meta Key for debug, enabled if above checks passed.
								//echo '<meta property="httpbl" content="enabled" />';
								$testenabled = getOption('zenHttpbl_enabletest');
								$testip      = getOption('zenHttpbl_manualtestip');
								if (($testenabled == 1) && ($testip != "" || NULL)) {
												//Query the manual test IP from zenHttpbl options.
												echo 'Testing: ' . ($apikey . "." . implode(".", array_reverse(explode(".", $testip))) . ".dnsbl.httpbl.org");
												$blresult = explode(".", gethostbyname($apikey . "." . implode(".", array_reverse(explode(".", $testip))) . ".dnsbl.httpbl.org"));
								} else {
												//Query against HTTP:BL DNS service.
												$detected_ip = $_SERVER["REMOTE_ADDR"];
												$blresult    = explode(".", gethostbyname($apikey . "." . implode(".", array_reverse(explode(".", $detected_ip))) . ".dnsbl.httpbl.org"));
								}
								//Check that we received an actual result, if not return.
								if ($blresult == gethostbyname($apikey . "." . implode(".", array_reverse(explode(".", $_SERVER["REMOTE_ADDR"]))) . ".dnsbl.httpbl.org")) {
												return;
								} else {
												// DNS provided results.
												if ($blresult[0] == "127") {
																$resolved = true;
																//Check against age of threat option.
																if ($blresult[1] <= getOption('zenHttpbl_ageofthreat')) {
																				$ageofthreat = true;
																}
																//Check against threat rating option.
																if ($blresult[2] >= getOption('zenHttpbl_threatrating')) {
																				$threatrating = true;
																}
												}
								}
								if (($ageofthreat == true) || ($threatrating == true)) {
												//Increment bad event count the save data to database, if enabled.
												$eventcount = getOption('zenHttpbl_eventcount');
												$badevents  = getOption('zenHttpbl_badevents');
												if ($eventcount == 1) {
																$badevents++;
																setOption('zenHttpbl_badevents', $badevents, TRUE);
												}
												//HTTP:BL request was resolved and threat is triggered from user defined options
												//If Honey Pot Link defined, redirect to it.
												if (($hp != "") && ($hp != NULL)) {
																header("HTTP/1.1 301 Moved Permanently ");
																header("Location: " . $hp . "");
												} elseif (($ql != "") && ($ql != NULL)) {
																header("HTTP/1.1 301 Moved Permanently ");
																header("Location: " . $hp . "");
												}
												// Exit if redirect to Honey Pot link failed.
												exit();
								}
				}
}
function zenHoneyPotLinks() {
				/*
				Insert your Honey Pot links and/or Project Honey Pot QuickLinks into theme
				files right after body and right before body close.
				
				I'm toying with the option of having checkbox options to select where in theme
				to insert the invisible links.  Perhaps in the next version.
				*/
				$hp   = getOption('zenHttpbl_honeypotlink');
				$hpql = getOption('zenHttpbl_honeypotquicklink');
				if (($hp != NULL) && ($hp != "")) {
								echo '<a href="' . $hp . '"><div style="height: 0px; width: 0px;"></div></a>';
				}
				if (($hpql != NULL) && ($hpql != "")) {
								echo '<a href="' . $hpql . '"><div style="height: 0px; width: 0px;"></div></a>';
				}
}

/*
Print a template call to display the # of bad events blocked.
Show off your spam-free site!
<?php if (function_exists('printBlockedEvents')) { printBlockedEvents(); } ?>
*/
function printBlockedEvents() {
		?>
		<div class="httpbl_box" id="httpbl_blocked">
		<?php
		echo '<b>Currently # of blocked bad events: <em>' . getOption('zenHttpbl_badevents') . '</em></b>';
		?>
		</div>
		<?php
}
?>