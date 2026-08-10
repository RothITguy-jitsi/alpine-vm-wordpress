<?php
/**
 * Logic tests for the MFA enforcement mu-plugin (03-wpvm-mfa-enforce.php).
 *
 * The mu-plugin's blocking decision is exactly the kind of thing that is easy
 * to get subtly wrong -- an off-by-one in the grace maths, or treating email
 * as a sufficient second factor -- and a mistake either locks admins out or
 * silently fails open. This exercises the pure decision functions against a
 * mocked WordPress surface so a regression is caught before it reaches a VM.
 *
 * Run: php test/test-mfa-enforcement.php
 */
define('ABSPATH', sys_get_temp_dir());
define('DAY_IN_SECONDS', 86400);
define('HOUR_IN_SECONDS', 3600);

class WP_User { public $ID; public $_admin; function __construct($id,$admin){$this->ID=$id;$this->_admin=$admin;} }
$GLOBALS['_meta'] = []; $GLOBALS['_providers'] = [];
function get_user_meta($id,$k,$s){ return $GLOBALS['_meta']["$id:$k"] ?? ''; }
function update_user_meta($id,$k,$v){ $GLOBALS['_meta']["$id:$k"]=$v; return true; }
function user_can($u,$cap){ return $cap==='manage_options' ? $u->_admin : false; }
class Two_Factor_Core {
  static function get_enabled_providers_for_user($id){ return $GLOBALS['_providers'][$id] ?? []; }
  // Real plugin returns classname => instance; mock mirrors the KEYS the code reads.
  static function get_available_providers_for_user($id){
    $flat = $GLOBALS['_providers'][$id] ?? [];
    $keyed = []; foreach($flat as $c){ $keyed[$c] = true; } return $keyed;
  }
}
function add_action(){} function add_filter(){}
function wp_doing_ajax(){ return $GLOBALS['_ajax'] ?? false; }
function wp_get_current_user(){ return $GLOBALS['_current'] ?? null; }
function wp_safe_redirect($u){ $GLOBALS['_redirected']=$u; }
function admin_url($p=''){ return 'https://site/wp-admin/'.$p; }
function in_array_poly(){ }

$file = dirname(__DIR__) . '/payload/mu-plugins/03-wpvm-mfa-enforce.php';
$src = file_get_contents($file);
$src = str_replace(['WPVM_MFA_ENFORCE_PLACEHOLDER','WPVM_MFA_GRACE_PLACEHOLDER'], ['1','7'], $src);
$src = preg_replace('/^<\?php/', '', $src);
eval($src);

$pass=0; $fail=0;
function check($d,$g,$w){ global $pass,$fail;
  if($g===$w){$pass++;} else {$fail++; echo "  FAIL: $d (got ".var_export($g,true).", want ".var_export($w,true).")\n";} }

$admin=new WP_User(1,true); $editor=new WP_User(2,false);
check('admin in scope', wpvm_mfa_user_in_scope($admin), true);
check('editor not in scope', wpvm_mfa_user_in_scope($editor), false);
check('null not in scope', wpvm_mfa_user_in_scope(null), false);

$GLOBALS['_providers'][1]=[];                       check('none=not enrolled', wpvm_mfa_user_enrolled(1), false);
$GLOBALS['_providers'][1]=['Two_Factor_Email'];     check('email-only=not enrolled', wpvm_mfa_user_enrolled(1), false);
$GLOBALS['_providers'][1]=['Two_Factor_Totp'];      check('TOTP=enrolled', wpvm_mfa_user_enrolled(1), true);
$GLOBALS['_providers'][1]=['Two_Factor_Backup_Codes']; check('backup codes=enrolled', wpvm_mfa_user_enrolled(1), true);

$GLOBALS['_meta']=[];                               check('first check anchors, not expired', wpvm_mfa_grace_expired(3), false);
$GLOBALS['_meta']['4:wpvm_mfa_grace_start']=time()-(8*86400); check('8d>7d grace=expired', wpvm_mfa_grace_expired(4), true);
$GLOBALS['_meta']['5:wpvm_mfa_grace_start']=time()-(3*86400); check('3d<7d grace=ok', wpvm_mfa_grace_expired(5), false);

$GLOBALS['_providers'][1]=[]; $GLOBALS['_meta']['1:wpvm_mfa_grace_start']=time()-(10*86400);
check('unenrolled admin past grace=BLOCK', wpvm_mfa_user_in_scope($admin)&&!wpvm_mfa_user_enrolled(1)&&wpvm_mfa_grace_expired(1), true);
$GLOBALS['_providers'][1]=['Two_Factor_Totp'];
check('enrolled admin=no block', !wpvm_mfa_user_enrolled(1), false);
$GLOBALS['_providers'][2]=[];
check('editor=never block', wpvm_mfa_user_in_scope($editor), false);

// ── enrollment-path gate: the lockout-critical function ──────────────────────
// If this wrongly blocks the profile or the TOTP setup endpoints, an unenrolled
// admin past grace is redirected away from the one page they need -> lockout.
function set_page($p){ $GLOBALS['pagenow']=$p; $_REQUEST=[]; }
set_page('profile.php');       check('profile.php is an enrollment path', wpvm_mfa_request_is_enrollment_path(), true);
set_page('user-edit.php');     check('user-edit.php (self-edit) allowed', wpvm_mfa_request_is_enrollment_path(), true);
set_page('admin-ajax.php');    check('admin-ajax.php (TOTP verify) allowed', wpvm_mfa_request_is_enrollment_path(), true);
set_page('admin-post.php');    check('admin-post.php (provider save) allowed', wpvm_mfa_request_is_enrollment_path(), true);
set_page('wp-login.php');      check('wp-login.php (logout) allowed', wpvm_mfa_request_is_enrollment_path(), true);
set_page('index.php'); $_REQUEST['action']='logout'; check('logout action allowed anywhere', wpvm_mfa_request_is_enrollment_path(), true);
set_page('edit.php'); $_REQUEST=[]; check('a normal admin page is NOT an enrollment path', wpvm_mfa_request_is_enrollment_path(), false);
set_page('plugins.php');       check('plugins.php is NOT an enrollment path', wpvm_mfa_request_is_enrollment_path(), false);

if($fail>0){ echo "MFA enforcement: $fail FAILED\n"; exit(1); }
echo "MFA enforcement logic: all $pass checks passed\n";
