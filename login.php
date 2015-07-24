<?php 
/**
 * @author Tim St.Clair - timst.clair@gmail.com
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package local/wp2moodle
 * @version 1.0
 * 
 * Moodle-end component of the wpMoodle Wordpress plugin.
 * Accepts user details passed across from Wordpress, creates a user in Moodle, authenticates them, and enrols them in the specified Cohort(s) or Group(s)
 *
 * 2012-05  Created
 * 2014-04  Added option to bypass updating user record for existing users
 *			Added option to enrol user into multiple cohorts or groups by specifying comma-separated list of identifiers
**/

// error_reporting(E_ALL);
// ini_set('display_errors', '1');

global $CFG, $USER, $SESSION, $DB;

require('../../config.php');
require_once($CFG->libdir.'/moodlelib.php');
require_once($CFG->dirroot.'/cohort/lib.php');
require_once($CFG->dirroot.'/group/lib.php');

// logon may somehow modify this
$SESSION->wantsurl = $CFG->wwwroot.'/';

// $PASSTHROUGH_KEY = "the quick brown fox humps the lazy dog"; // must match wp2moodle wordpress plugin setting
$PASSTHROUGH_KEY = get_config('auth/wp2moodle', 'sharedsecret');
if (!isset($PASSTHROUGH_KEY)) {
	echo "Sorry, this plugin has not yet been configured. Please contact the Moodle administrator for details.";
}

/**
 * Handler for decrypting incoming data (specially handled base-64) in which is encoded a string of key=value pairs
 */
function decrypt_string($base64, $key) {
	if (!$base64) { return ""; }
	$data = str_replace(array('-','_'),array('+','/'),$base64); // manual de-hack url formatting
    $mod4 = strlen($data) % 4; // base64 length must be evenly divisible by 4
    if ($mod4) {
        $data .= substr('====', $mod4);
    }
    $crypttext = base64_decode($data);
    $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
    $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
    $decrypttext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($key.$key), $crypttext, MCRYPT_MODE_ECB, $iv);
	return trim($decrypttext);
}

/**
 * querystring helper, returns the value of a key in a string formatted in key=value&key=value&key=value pairs, e.g. saved querystrings
 */
function get_key_value($string, $key) {
    $list = explode( '&', $string);
    foreach ($list as $pair) {
    	$item = explode( '=', $pair);
		if (strtolower($key) == strtolower($item[0])) {
			return urldecode($item[1]); // not for use in $_GET etc, which is already decoded, however our encoder uses http_build_query() before encrypting
		}
    }
    return "";
}

// truncate_userinfo requires and returns an array
// but we want to send in and return a user object
function truncate_user($userobj) {
	$user_array = truncate_userinfo((array) $userobj);
	$obj = new stdClass();
	foreach($user_array as $key=>$value) {
	    $obj->{$key} = $value;
	}
	return $obj;
}

$rawdata = $_GET['data'];
if (!empty($_GET)) {


	// get the data that was passed in
	$userdata = decrypt_string($rawdata, $PASSTHROUGH_KEY);

	// time (in minutes) before incoming link is considered invalid
	$timeout = (integer) get_config('auth/wp2moodle', 'timeout');
	if ($timeout == 0) { $timeout = 5; }

	// check the timestamp to make sure that the request is still within a few minutes of this servers time
	// if userdata didn't decrypt, then timestamp will = 0, so following code will be bypassed anyway (e.g. bad data)
	$timestamp = (integer) get_key_value($userdata, "stamp"); // remote site should have set this to new DateTime("now").getTimestamp(); which is a unix timestamp (utc)
	$theirs = new DateTime("@$timestamp"); // @ format here: http://www.gnu.org/software/tar/manual/html_node/Seconds-since-the-Epoch.html#SEC127
	$diff = floatval(date_diff(date_create("now"), $theirs)->format("%i")); // http://www.php.net/manual/en/dateinterval.format.php
	
	if ($timestamp > 0 && $diff <= $timeout) { // less than N minutes passed since this link was created, so it's still ok
		
		$username = trim(strtolower(get_key_value($userdata, "username"))); // php's tolower, not moodle's
		$hashedpassword = get_key_value($userdata, "passwordhash");
		$firstname = get_key_value($userdata, "firstname"); if (empty($firstname)===true) { $firstname = 'no-firstname'; }
		$lastname = get_key_value($userdata, "lastname"); if (empty($lastname)===true) { $lastname = 'no-lastname'; }
		$email = get_key_value($userdata, "email");
		$idnumber = get_key_value($userdata, "idnumber"); // the users id in the wordpress database, stored here for possible user-matching
		$cohort = get_key_value($userdata, "cohort"); // the cohort to map the user user; these can be set as enrolment options on one or more courses, if it doesn't exist then skip this step
		$group = get_key_value($userdata, "group");
		$updatefields = (get_key_value($userdata, "updatable") != "false");	// if true or not set, update fields like email, username, etc.
		
		// mdl_user.idnumber is the wordpress wp_users.id
		// TODO: if (get_field('user', 'id', 'username', $username, 'deleted', 1, '')) ----> error since the user is now deleted

        if ($DB->record_exists('user', array('username'=>$username, 'idnumber'=>'', 'auth'=>'manual'))) { // update manually created user that has the same username but doesn't yet have the right idnumber
			$updateuser = get_complete_user_data('username', $username);
			$updateuser->idnumber = $idnumber;
			if ($updatefields) {
				$updateuser->email = $email;
				$updateuser->firstname = $firstname;
				$updateuser->lastname = $lastname;
			}
			// do not update username
			// do not update password, we don't know it

			// make sure we haven't exceeded any field limits
			$updateuser = truncate_user($updateuser); // typecast obj to array, works just as well

			$updateuser->timemodified = time(); // record that we changed the record
			$DB->update_record('user', $updateuser);

			// trigger correct update event
            events_trigger('user_updated', $DB->get_record('user', array('idnumber'=>$idnumber)));
			
			// ensure we have the latest data
			$user = get_complete_user_data('idnumber', $idnumber);

        } else if ($DB->record_exists('user', array('idnumber'=>$idnumber))) { // match user on idnumber
			if ($updatefields) {
				$updateuser = get_complete_user_data('username', $username);
				$updateuser->idnumber = $idnumber;
				$updateuser->email = $email;
				$updateuser->firstname = $firstname;
				$updateuser->lastname = $lastname;
				$updateuser->username = $username;

				$updateuser = truncate_user($updateuser); // make sure we haven't exceeded any field limits
				$updateuser->timemodified = time(); // when we last changed the data in the record

				$DB->update_record('user', $updateuser);
	
				// trigger correct update event
	            events_trigger('user_updated', $DB->get_record('user', array('idnumber'=>$idnumber)));
			}
			// ensure we have the latest data
			$user = get_complete_user_data('idnumber', $idnumber);
			
		} else { // create new user
			//code based on moodlelib.create_user_record($username, $password, 'manual')
			$auth = 'wp2moodle'; // so they log in - and out - with this plugin
		    $authplugin = get_auth_plugin($auth);
		    $newuser = new stdClass();
			if ($newinfo = $authplugin->get_userinfo($username)) {
				$newinfo = truncate_user($newinfo);
				foreach ($newinfo as $key => $value){
				    $newuser->$key = $value;
				}
			}

		    if (!empty($newuser->email)) {
		        if (email_is_not_allowed($newuser->email)) {
		            unset($newuser->email);
		        }
		    }
		    if (!isset($newuser->city)) {
		        $newuser->city = '';
		    }
		    $newuser->auth = $auth;
			$newuser->policyagreed = 0;
			$newuser->idnumber = $idnumber;
		    $newuser->username = $username;
	        $newuser->password = md5($hashedpassword); // manual auth checks password validity, so we need to set a valid password

	        // $DB->set_field('user', 'password',  $hashedpassword, array('id'=>$user->id));
   			$newuser->firstname = $firstname;
			$newuser->lastname = $lastname;
			$newuser->email = $email;
		    if (empty($newuser->lang) || !get_string_manager()->translation_exists($newuser->lang)) {
		        $newuser->lang = $CFG->lang;
		    }
		    $newuser->confirmed = 1; // don't want an email going out about this user
		    $newuser->lastip = getremoteaddr();
		    $newuser->timecreated = time();
		    $newuser->timemodified = $newuser->timecreated;
		    $newuser->mnethostid = $CFG->mnet_localhost_id;

			// make sure we haven't exceeded any field limits
			$newuser = truncate_user($newuser);

		    $newuser->id = $DB->insert_record('user', $newuser);

		    $user = get_complete_user_data('id', $newuser->id);
		    events_trigger('user_created', $DB->get_record('user', array('id'=>$user->id)));

		}

        $count = 0;
        require_once($CFG->libdir.'/csvlib.class.php');
        require_once($CFG->dirroot.'/group/lib.php');
        require_once($CFG->dirroot.'/cohort/lib.php');
        $fs = get_file_storage();
        $files = $DB->get_records('files', array('component' => 'local_usermapping'));
        foreach ($files as $file) {
            if ($file->filename == '.') {
                continue;
            }
            $fileinfo = (array) $file;
            $storedfile = $fs->get_file($fileinfo['contextid'], $fileinfo['component'], $fileinfo['filearea'],
                      $fileinfo['itemid'], $fileinfo['filepath'], $fileinfo['filename']);

            $count++;
            $csvcontent =  $storedfile->get_content();
            $iid = csv_import_reader::get_new_iid('userfile' . $count);
            $cir = new csv_import_reader($iid, 'userfile' . $count);
            
            $readcount = $cir->load_csv_content($csvcontent, 'utf8', ',');
            $columns = $cir->get_columns();

            $filecolumns = array();
            foreach ($columns as $key=>$unused) {
                $field = $columns[$key];
                $lcfield = core_text::strtolower($field);
                $filecolumns[$key] = $lcfield;
            }

            $users = array();
            $cir->init();
            $founduser = false;
            while ($line = $cir->next()) {
                $spuser = new Object;

                foreach ($line as $keynum => $value) {
                    if (!isset($filecolumns[$keynum])) {
                        // this should not happen
                        continue;
                    }
                    $key = $filecolumns[$keynum];
                    $spuser->$key = $value;
                }
                if ($spuser->username == $user->username) {
                    $founduser = clone($spuser);
                    $founduser->id = $user->id;
                }
            }


            $manualcache = array();
            $ccache = array();
            $rolecache = array();
            $cohorts = array();

            if (enrol_is_enabled('manual')) {
                $manual = enrol_get_plugin('manual');
            } else {
                $manual = NULL;
            }
            $today = time();
            $today = make_timestamp(date('Y', $today), date('m', $today), date('d', $today), 0, 0, 0);

            $allowedroles = $DB->get_records('role');
            foreach ($allowedroles as $role) {
                $rolecache[$role->id] = new stdClass();
                $rolecache[$role->id]->id   = $role->id;
                $rolecache[$role->id]->name = $role->shortname;
            }

            // $dbf = $CFG->dataroot . '/temp/' . $file->filename; 
            // $fh = fopen($dbf, 'w');
            // fwrite($fh, print_r($founduser, true));

            // add to cohort first, it might trigger enrolments indirectly - do NOT create cohorts here!
            foreach ($filecolumns as $column) {
                if (!preg_match('/^cohort\d+$/', $column)) {
                    continue;
                }

                if (!empty($founduser->$column)) {
                    $addcohort = $founduser->$column;
                    if (!isset($cohorts[$addcohort])) {
                        if (is_number($addcohort)) {
                            // only non-numeric idnumbers!
                            $cohort = $DB->get_record('cohort', array('id'=>$addcohort));
                        } else {
                            $cohort = $DB->get_record('cohort', array('idnumber'=>$addcohort));
                        }

                        if (empty($cohort)) {
                            $cohorts[$addcohort] = get_string('unknowncohort', 'core_cohort', s($addcohort));
                        } else if (!empty($cohort->component)) {
                            // cohorts synchronised with external sources must not be modified!
                            $cohorts[$addcohort] = get_string('external', 'core_cohort');
                        } else {
                            $cohorts[$addcohort] = $cohort;
                        }
                    }

                    if (is_object($cohorts[$addcohort])) {
                        $cohort = $cohorts[$addcohort];
                        if (!$DB->record_exists('cohort_members', array('cohortid'=>$cohort->id, 'userid'=>$user->id))) {
                            cohort_add_member($cohort->id, $founduser->id);
                        }
                    }
                }
            }

            foreach ($filecolumns as $column) {
                if (!preg_match('/^course\d+$/', $column)) {
                    continue;
                }
                $i = substr($column, 6);

                if (empty($founduser->{'course'.$i})) {
                    continue;
                }
                $shortname = $founduser->{'course'.$i};
                
                if (!array_key_exists($shortname, $ccache)) {
                    if (!$course = $DB->get_record('course', array('shortname'=>$shortname), 'id, shortname')) {
                        continue;
                    }
                    $ccache[$shortname] = $course;
                    $ccache[$shortname]->groups = null;
                }
                $courseid      = $ccache[$shortname]->id;
                $coursecontext = context_course::instance($courseid);
                if (!isset($manualcache[$courseid])) {
                    $manualcache[$courseid] = false;
                    if ($manual) {
                        if ($instances = enrol_get_instances($courseid, false)) {
                            foreach ($instances as $instance) {
                                if ($instance->enrol === 'manual') {
                                    $manualcache[$courseid] = $instance;
                                    break;
                                }
                            }
                        }
                    }
                }

                if ($manual and $manualcache[$courseid]) {
                    //fwrite($fh, 'enrolling in ' . $courseid . "\n");
                    // find role
                    $rid = false;
                    if (!empty($founduser->{'role'.$i})) {
                        $rid = $founduser->{'role'.$i};
                    }
                    
                    if (!$rid) {
                        $rid = $manualcache[$courseid]->roleid;
                    }
                    //fwrite($fh, 'roleid in ' . $rid . "\n");
                    if ($rid) {
                        // Find duration and/or enrol status.
                        $timeend = 0;
                        $status = null;

                        if (isset($founduser->{'enrolstatus'.$i})) {
                            $enrolstatus = $founduser->{'enrolstatus'.$i};
                            if ($enrolstatus == '') {
                                $status = null;
                            } else if ($enrolstatus === (string)ENROL_USER_ACTIVE) {
                                $status = ENROL_USER_ACTIVE;
                            } else if ($enrolstatus === (string)ENROL_USER_SUSPENDED) {
                                $status = ENROL_USER_SUSPENDED;
                            } else {
                                
                            }
                        }

                        if (!empty($founduser->{'enrolperiod'.$i})) {
                            $duration = (int)$founduser->{'enrolperiod'.$i} * 60*60*24; // convert days to seconds
                            if ($duration > 0) { // sanity check
                                $timeend = $today + $duration;
                            }
                        } else if ($manualcache[$courseid]->enrolperiod > 0) {
                            $timeend = $today + $manualcache[$courseid]->enrolperiod;
                        }

                        $manual->enrol_user($manualcache[$courseid], $founduser->id, $rid, $today, $timeend, $status);

                        $a = new stdClass();
                        $a->course = $shortname;
                        $a->role   = $rolecache[$rid]->name;
                    }
                }

                // find group to add to
                if (!empty($founduser->{'group'.$i})) {
                    // make sure user is enrolled into course before adding into groups
                    if (!is_enrolled($coursecontext, $founduser->id)) {
                        continue;
                    }
                    //build group cache
                    if (is_null($ccache[$shortname]->groups)) {
                        $ccache[$shortname]->groups = array();
                        if ($groups = groups_get_all_groups($courseid)) {
                            foreach ($groups as $gid=>$group) {
                                $ccache[$shortname]->groups[$gid] = new stdClass();
                                $ccache[$shortname]->groups[$gid]->id   = $gid;
                                $ccache[$shortname]->groups[$gid]->name = $group->name;
                                if (!is_numeric($group->name)) { // only non-numeric names are supported!!!
                                    $ccache[$shortname]->groups[$group->name] = new stdClass();
                                    $ccache[$shortname]->groups[$group->name]->id   = $gid;
                                    $ccache[$shortname]->groups[$group->name]->name = $group->name;
                                }
                            }
                        }
                    }
                    // group exists?
                    $addgroup = $founduser->{'group'.$i};
                    if (!array_key_exists($addgroup, $ccache[$shortname]->groups)) {
                        // if group doesn't exist,  create it
                        $newgroupdata = new stdClass();
                        $newgroupdata->name = $addgroup;
                        $newgroupdata->courseid = $ccache[$shortname]->id;
                        $newgroupdata->description = '';
                        $gid = groups_create_group($newgroupdata);
                        if ($gid){
                            $ccache[$shortname]->groups[$addgroup] = new stdClass();
                            $ccache[$shortname]->groups[$addgroup]->id   = $gid;
                            $ccache[$shortname]->groups[$addgroup]->name = $newgroupdata->name;
                        } else {
                            continue;
                        }
                    }
                    $gid   = $ccache[$shortname]->groups[$addgroup]->id;
                    $gname = $ccache[$shortname]->groups[$addgroup]->name;
                }
            }
            $cir->close();
            $cir->cleanup();

            //fclose($fh);
        }

		// if we can find a cohortid matching what we sent in, enrol this user in that cohort by adding a record to cohort_members
		// if (!empty($cohort)) {
		// 	$ids = explode(',',$cohort);
		// 	foreach ($ids as $cohort) {
		// 		if ($DB->record_exists('cohort', array('idnumber'=>$cohort))) {
		// 	        $cohortrow = $DB->get_record('cohort', array('idnumber'=>$cohort));
		// 			if (!$DB->record_exists('cohort_members', array('cohortid'=>$cohortrow->id, 'userid'=>$user->id))) {
		// 				// internally triggers cohort_member_added event
		// 				cohort_add_member($cohortrow->id, $user->id);
		// 			}
					
		// 			// if the plugin auto-opens the course, then find the course this cohort enrols for and set it as the opener link
		// 			if (get_config('auth/wp2moodle', 'autoopen') == 'yes')  {
		// 		        if ($enrolrow = $DB->get_record('enrol', array('enrol'=>'cohort','customint1'=>$cohortrow->id,'status'=>0))) {
		// 					$SESSION->wantsurl = new moodle_url('/course/view.php', array('id'=>$enrolrow->courseid));
		// 				}
		// 			}
		// 		}
		// 	}
		// }

		// also optionally find a groupid we sent in, enrol this user in that group, and optionally open the course
		// if (!empty($group)) {
		// 	$ids = explode(',',$group);
		// 	foreach ($ids as $group) {
		// 		if ($DB->record_exists('groups', array('idnumber'=>$group))) {
		// 	        $grouprow = $DB->get_record('groups', array('idnumber'=>$group));
		// 			if (!$DB->record_exists('groups_members', array('groupid'=>$grouprow->id, 'userid'=>$user->id))) {
		// 				// internally triggers groups_member_added event
		// 				groups_add_member($grouprow->id, $user->id); //  not a component ,'enrol_wp2moodle');
		// 			}
					
		// 			// if the plugin auto-opens the course, then find the course this group is for and set it as the opener link
		// 			if (get_config('auth/wp2moodle', 'autoopen') == 'yes')  {
		// 				$SESSION->wantsurl = new moodle_url('/course/view.php', array('id'=>$grouprow->courseid));
		// 			}
		// 		}
		// 	}
		// }	
		
		// all that's left to do is to authenticate this user and set up their active session
	    $authplugin = get_auth_plugin('wp2moodle'); // me!
		if ($authplugin->user_login($user->username, null)) {
			$user->loggedin = true;
			$user->site     = $CFG->wwwroot;
			complete_user_login($user);
	        add_to_log(SITEID, 'user', 'login', "view.php?id=$user->id&course=".SITEID,$user->id, 0, $user->id);
		}
		

	}
	
}

// redirect to the homepage
redirect($SESSION->wantsurl);
?>
