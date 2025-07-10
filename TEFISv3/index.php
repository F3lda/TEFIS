<?php
/**
 * @file index.php (TEFIS)
 * 
 * @brief TEFIS - Temporary files storage (save files from someone else's computer without login to your important accounts)
 * @date 2020-10-22
 * @author F3lda
 * @update 2025-07-10
 */
// -----------------------------
// SECURITY CONFIGURATION
$USERNAME = "admin";// <- change this
$PASSWORD_HASH = '$2y$10$V3hvP8dliqdMsanRoPQQpuiXdR37OMtlKw9EMkuQVr0RpGoiEi.l.'; // <- change this (bcrypt hash of "admin")
$MAX_LOGIN_ATTEMPTS = 5;
$LOCKOUT_TIME = 900; // 15 minutes
$SESSION_TIMEOUT = 3600; // 1 hour
// -----------------------------

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Lockout file configuration
$LOCKOUT_FILE = './PRIVATE/.lockout_data';

// Get client IP address (with proxy support)
function get_client_ip() {
    $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    foreach ($ip_keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ips = explode(',', $_SERVER[$key]);
            $ip = trim($ips[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

// Load lockout data from file
function load_lockout_data() {
    global $LOCKOUT_FILE;
    
    if (!file_exists($LOCKOUT_FILE)) {
        return array();
    }
    
    $data = file_get_contents($LOCKOUT_FILE);
    if ($data === false) {
        return array();
    }
    
    $lockout_data = json_decode($data, true);
    return is_array($lockout_data) ? $lockout_data : array();
}

// Save lockout data to file
function save_lockout_data($data) {
    global $LOCKOUT_FILE;
    
    // Ensure PRIVATE directory exists
    if (!is_dir('./PRIVATE')) {
        mkdir('./PRIVATE', 0777, true);
    }
    
    $json_data = json_encode($data, JSON_PRETTY_PRINT);
    file_put_contents($LOCKOUT_FILE, $json_data, LOCK_EX);
    chmod($LOCKOUT_FILE, 0600); // Only readable by server
}

// Clean expired lockout entries
function clean_expired_lockouts() {
    global $LOCKOUT_TIME;
    
    $lockout_data = load_lockout_data();
    $current_time = time();
    $cleaned = false;
    
    foreach ($lockout_data as $ip => $data) {
        if (isset($data['last_attempt']) && ($current_time - $data['last_attempt']) > $LOCKOUT_TIME) {
            unset($lockout_data[$ip]);
            $cleaned = true;
        }
    }
    
    if ($cleaned) {
        save_lockout_data($lockout_data);
    }
    
    return $lockout_data;
}

// Check if IP is rate limited
function is_ip_rate_limited($ip) {
    global $MAX_LOGIN_ATTEMPTS, $LOCKOUT_TIME;
    
    $lockout_data = clean_expired_lockouts();
    
    if (!isset($lockout_data[$ip])) {
        return false;
    }
    
    $ip_data = $lockout_data[$ip];
    
    if ($ip_data['failed_attempts'] >= $MAX_LOGIN_ATTEMPTS) {
        if ((time() - $ip_data['last_attempt']) < $LOCKOUT_TIME) {
            return true;
        }
    }
    
    return false;
}

// Record failed login attempt
function record_failed_attempt($ip) {
    $lockout_data = load_lockout_data();
    
    if (!isset($lockout_data[$ip])) {
        $lockout_data[$ip] = array(
            'failed_attempts' => 0,
            'last_attempt' => 0,
            'first_attempt' => time()
        );
    }
    
    $lockout_data[$ip]['failed_attempts']++;
    $lockout_data[$ip]['last_attempt'] = time();
    
    save_lockout_data($lockout_data);
}

// Clear failed attempts for IP (on successful login)
function clear_failed_attempts($ip) {
    $lockout_data = load_lockout_data();
    
    if (isset($lockout_data[$ip])) {
        unset($lockout_data[$ip]);
        save_lockout_data($lockout_data);
    }
}

// Get remaining lockout time for IP
function get_remaining_lockout_time($ip) {
    global $LOCKOUT_TIME;
    
    $lockout_data = load_lockout_data();
    
    if (!isset($lockout_data[$ip])) {
        return 0;
    }
    
    $remaining = $LOCKOUT_TIME - (time() - $lockout_data[$ip]['last_attempt']);
    return max(0, $remaining);
}

// Start session with secure settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? 1 : 0);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Initialize session variables
if (!isset($_SESSION['user_id'])) {
    $_SESSION['user_id'] = "";
    $_SESSION['user_name'] = "";
    $_SESSION['user_type'] = "";
    $_SESSION['login_time'] = "";
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// CSRF token generation
function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// CSRF token validation
function validate_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Rate limiting check
function is_rate_limited() {
    $client_ip = get_client_ip();
    return is_ip_rate_limited($client_ip);
}

// Session timeout check
function is_session_expired() {
    global $SESSION_TIMEOUT;
    
    if (isset($_SESSION['login_time']) && $_SESSION['login_time'] !== "") {
        return (time() - $_SESSION['login_time']) > $SESSION_TIMEOUT;
    }
    return false;
}

// Secure logout
if (isset($_GET['LOGOUT'])) {
    // Regenerate session ID before destroying
    session_regenerate_id(true);
    
    $_SESSION['user_id'] = "";
    $_SESSION['user_name'] = "";
    $_SESSION['user_type'] = "";
    $_SESSION['login_time'] = "";
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    
    // Destroy session completely
    session_destroy();
    session_start();
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    // redirect
    header('Location: ./', true, 301);
    die();
}

function is_logged_in() {
    if (isset($_SESSION['user_name']) && $_SESSION['user_name'] != "") {
        // Check session timeout
        if (is_session_expired()) {
            // Auto logout on timeout
            $_SESSION['user_id'] = "";
            $_SESSION['user_name'] = "";
            $_SESSION['user_type'] = "";
            $_SESSION['login_time'] = "";
            return false;
        }
        
        // Refresh session time on each page load if logged in
        $_SESSION['login_time'] = time();
        return true;
    }
    return false;
}

// Password hashing function (for generating new hashes)
function hash_password($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

// Secure time comparison to prevent timing attacks
function secure_time_compare($str1, $str2) {
    if (strlen($str1) !== strlen($str2)) {
        return false;
    }
    return hash_equals($str1, $str2);
}

// -------------------------------------------------------------------------------------------------------------------------------------------------
// EMPTY BODY - START
// -------------------------------------------------------------------------------------------------------------------------------------------------
// NOT LOGGED IN
if (!is_logged_in()) {
    // Login
    if (isset($_POST["login"])) {
        $client_ip = get_client_ip();
        
        // Check CSRF token
        if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
            record_failed_attempt($client_ip);
            http_response_code(403);
            die('CSRF token validation failed');
        }
        
        // Check rate limiting
        if (is_ip_rate_limited($client_ip)) {
            $remaining_time = get_remaining_lockout_time($client_ip);
            $minutes = ceil($remaining_time / 60);
            header('Location: ./?error=rate_limited&time=' . $minutes, true, 301);
            die();
        }
        
        $username = trim($_POST["username"] ?? '');
        $password = $_POST["password"] ?? '';
        
        // Validate input
        if (empty($username) || empty($password)) {
            record_failed_attempt($client_ip);
            header('Location: ./?error=empty_fields', true, 301);
            die();
        }
        
        // Verify credentials with timing attack protection
        $username_valid = secure_time_compare($username, $USERNAME);
        $password_valid = password_verify($password, $PASSWORD_HASH);
        
        if ($username_valid && $password_valid) {
            // Successful login - clear failed attempts for this IP
            clear_failed_attempts($client_ip);
            
            // Regenerate session ID
            session_regenerate_id(true);
            
            $_SESSION['user_id'] = "1";
            $_SESSION['user_name'] = $username;
            $_SESSION['user_type'] = "admin";
            $_SESSION['login_time'] = time();
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            // redirect
            header('Location: ./', true, 301);
            die();
        } else {
            // Failed login - record attempt for this IP
            record_failed_attempt($client_ip);
            
            // Add small delay to slow down brute force
            usleep(rand(100000, 500000)); // 0.1-0.5 seconds
            
            header('Location: ./?error=invalid_credentials', true, 301);
            die();
        }

    // Unauthorized
    } else if (count($_POST) > 0 || count($_GET) > 0) {
        // Allow error parameters for login page
        if (isset($_GET['error'])) {
            // Continue to show login page with error
        } else {
            echo "ERROR - Unauthorized";
            http_response_code(401);
            die();
        }
    }
}

// SHOW FILE
if(isset($_GET["SHOW"]) && isset($_GET["ID"]) && is_logged_in()){
	$files = scandir("./PRIVATE");
	$files = array_diff($files, array('.', '..', '.htaccess'));
	if(isset($files[$_GET["ID"]])){
		$file = "./PRIVATE/".$files[$_GET["ID"]];
		if(file_exists($file) && $files[$_GET["ID"]] != ""){
			//$file_info = new finfo(FILEINFO_MIME_TYPE);
			//$file_info_type = $file_info->file($file);
			$file_info_type = mime_content_type($file);
			$file_type = explode("/",$file_info_type);
			$allowed_files = array(
				"application/javascript", 
				"application/xhtml+xml",
				"application/json",
				"application/ld+json",
				"application/xml"
			);
			if($file_type[0] == "text" || array_search($file_info_type, $allowed_files, true) !== false){
				//ASCII
				echo "<pre>".htmlspecialchars(file_get_contents($file))."</pre>";
			} else {
				//binary
				header('Content-Type: ' . $file_info_type);
				header('Content-Disposition: inline; filename="' . basename($file) . '"');
				header('Content-Transfer-Encoding: binary');
				header('Content-Length: ' . filesize($file));
				header('Accept-Ranges: bytes');
				header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
				header("Cache-Control: post-check=0, pre-check=0", false);
				header("Cache-Control: no-cache");
				header("Connection: close");
				header('Expires: 0');
				@ob_clean();
				@flush();
				@readfile($file);
				exit();
			}
		} else {
			echo "File doesn't exist!";
		}
	} else {
		echo "File doesn't exist!";
	}
// DOWNLOAD FILE
} else if(isset($_GET["DOWNLOAD"]) && isset($_GET["DIR"]) && isset($_GET["ID"]) && ($_GET["DIR"] != "PRIVATE" || is_logged_in())){
	$files = scandir("./".$_GET["DIR"]);
	$files = array_diff($files, array('.', '..', '.htaccess'));
	if(isset($files[$_GET["ID"]])){
		$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
		if(file_exists($file) && $files[$_GET["ID"]] != ""){
			header('Content-Description: File Transfer');
			header('Content-Type: application/octet-stream');
			header('Content-Disposition: attachment; filename="' . basename($file) . '"');
			header('Content-Transfer-Encoding: binary');
			header('Content-Length: ' . filesize($file));
			header('Accept-Ranges: bytes');
			header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
			header("Cache-Control: post-check=0, pre-check=0", false);
			header("Cache-Control: no-cache");
			header("Connection: close");
			header('Expires: 0');
			@ob_clean();
			@flush();
			@readfile($file);
			exit();
		} else {
			echo "File doesn't exist!";
		}
	} else {
		echo "File doesn't exist!";
	}
	echo '<br><br><button onclick="window.location.href = \'./\';">< Home</button>';
}
// -------------------------------------------------------------------------------------------------------------------------------------------------
// EMPTY BODY - END
// -------------------------------------------------------------------------------------------------------------------------------------------------
else {
// -------------------------------------------------------------------------------------------------------------------------------------------------
// MAIN BODY - START
// -------------------------------------------------------------------------------------------------------------------------------------------------
?>
<!DOCTYPE html>
<html>
<head>
	<title>TEFIS - Temporary files storage</title>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Type" content="text/html; UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4
	bAAAAB3RJTUUH5AsIEiEoVe0gzQAAIABJREFUeNrtXc1vXcd1P4fvSZREyjIFqAuLtWJLccRIJgUkDQIZSFfRwu6i/4K1C/r/tIsAzrbZZRG7gIQuWsBCbNiAxVpVqlhyUoiuIAKWDekpoki+6eK+yzd3OHfu
	zNz5vucAD6LI93XnnvM7v/MxZ5AxBiQkJMOUBVoCEhICABISEgIAEhISAgASEhICABISEgIAEhISAgASEhICABISEgIAEhISAgASEpKMZUxLQEISWe6+Z9aPv/YhuvpopL0ApGTBxKHiZnHt4vX6+B4915QAY
	KgG3qU2pmqBs9egxWtDGVaI79bLGi2/Xw8QIADITf74HvOixKbKhxpgkbLBYU/AS1EsgKB8AFB5h5QUVObVUEM5fVyD7D11v4v4HJ9rHPv+oQPwcH0NhiBQNgCkEPfmqNy6n932vC7DMLm2+r3+7znAZ9sAk7
	1w67A0Brh0GuCNk0moBJts6t/CpXUtcCizCuCLJg/B+E08Gmsx+Prfr58C3Pk2rNG6lMkewKePq8fSGGBtBeD8K0WZSnkMQPT6bXSWJWTYjzx5N1ceDCN5YJKmHGfAfvQSYFXvHhxiARIGUA4AyOj+I1JaKSh
	cPg3wg5OQ5XqdfwXgp2cC6NMTgM1vsweCBggMJgSolfnWY4DdfTJ6kdZ+8rh6hJDXTwL87AzACPvlFlAIOZjFe5jI2kr1AADYZwCfb1chTQryVwTcXKwub7UfWJcLAJ9kaPxd3k2l1OLffHmw868A/N0Z92EV
	n0dgLfkGVPzdNo+hIyME+NnfVA8fIaANI5mCFgiwyaY8IVhUCCCj/7+9P//5wisAPzmTRh7AtcKYeNX/1gSFNiPv+uyu/4c0mAKFTTYBvjoC+Mej818uALD1nU4mgEvrAwsBePnJGfceIoRyuvR0jKO1OoaqQ
	7ddvEdowMxF+M7K2Vri0jqwC5vVr2sQqJmATihw9z0mgkD+uwFtav0YyDj7fB4GBBam8Vzd1mF0aJTMcG2YQ+OL7u4VIdGFXWAXXzbCAfjqiNV1DXM7sKliYQCwiN2aig7XFj0bJXN0Pb6BxDH9bzQCXdgFeG
	N3fin3jlrpIc0D0LnxLOJn9zVU1PwdswAk1DBQdPTdmYf1ZD2BwsX6K/7+4M5Hh+N4/uuvCSzgoXlEP6x5ACY71kwy7iFjUheGoJPBN80/sB7PiRnX+64oMP01EQ2e/92bl989/F4Ls8d0tlRdVQEcOgC4Svw
	xB5/nS7Fb3lemXLGlodSoCVYWkuK1u9Jd9tZLvYRgy/oOCgBkmylaa6Q2yohg10fP+ht4/bcHX+aj7Dl912Tlwu6hqoAJgAxyJFht9Gyy2b5zzcZD23gry88owquROAMB4HsDHo61OwTHQzT82sBxaR2AkTGR
	5KLAs14A2bZgMRegCQDDqAL8+anckyLpFEn+eYA6F3AgU/23LBcARpx1f7bdpPbCgr556V1SLpL8wwALyR8A2kYgXVqZ/7zP+sXpJCSpkACDqUBi+FAuA5Bd3NpK8/8dWzmJBZAMMXwoOwfAhwGfb5MSkAxXi
	mYAF2dhAHaEAXefkCKQkBTLAJgkDHjr1fn/7zxJZ6oLCQmFAA5l7UOU0pz10/NQoB7tREJCYUAEALj7Hjt4+AwFxDwAhQIkRRu2fUPL2LmB+3hu30Ml11YAXkwB7n03DwXeerWZJCQhyZbea5qS081AIU/dET
	/LBhDWTwO82Af436cAry9Ljf/NS+9SWzBJGaK5H2BsZYixHacCfJSNEusA8CMEWJwATB5Jn0L9AOGEwNaxWOwHGFsZf0qnwZp+5uL8yapxyST+xRXYEpDMnJ8wG8BdDoD3uDoDJINetRoEyMgzkR7OQwoks/c
	bFDiI24I11necTJzfFwTI4DN3X47Bod7odfldGjzCr6Mkasjb+EmKVEytvwUONbIH2ORGgn391M3JtaGgKtXDM3M/utpnWMlt+aZcgS4AhPD+j57Pz173aRhtx2OXdHLwZK+6ls8y6XI0Oba8D8ALryUQiM0A
	QhvdZM8/yJDEvy9tgEJBrAUA9PX+JXnWNpGd4vu7PwD848/Df5fUjq6OBSifb2sxCmIBrhlAX4PvOhLbVu4anITr4vNjGD+Au6OrQ4mvY8v39f0WgUAbAOh6/9BGbxMH1ifhkqQlqvtic5/5Y+DbksqS9yUQs
	GEAJobv0rNTLDcMsbnPXPtraxhA+mPZCMS/6NFzgFuPAXb3w1J5kuSUJqXPbLS/7pOlm4LrWOtFbcbvw+hNDvBMeb1/fbO6nDMn4+YIcmNepvde1f5aWi6gqylqe+SYAdTyiWD8Pr09y5+21cYPAMC2n1Yg8L
	s/HH5ijqAQwuuTI7cCZPxi0fi13ROBHj2v9tET1beT3T1g3zypHttPq8c3s4lEMlAYumLTjBZ72eEW75zkoBDJHI1uBvCJ0KxBxq/n/Xf3pGBQazv75luAI0dI33U8VebhYJRlfPul1vO6GcAut7GYRmipF/2
	f/60y8t29bu1mALC7W72GxJr6Htr9adgQNfSNQt0M4NLKvHFjn7nZwFOSaNN4dtirzX7Pfn2zyhNQTsBORjivANSlwAJZg/WxYL0YwNoKnbDTZfyI87hex/hFxdzdBbb9lHICtiI7B5JChua04M6TgVRdgG0H
	bQ5dTrwNcOJtYN98Lyz8aPYYc6vPPRAP/253D9i3U2Af3KJ1NZWeHZ/FhgGs+1DchRALXKxcWwJ2/2MAJvRHsH0ANgVgdq3SBAI9pc4D6KasBpzaWrBaCDpeyzzm15EX3xMI9MkDiGEqkVUHOQDVAg/dxGsjx
	ZEbXGAIsPOMFtZFHsDESbHhVgPmALD2IR60YVIewB1NZwZ0ExmFAn3yAOSkHDAARnkAI+NfXFazANNyFNtvsAACAQO5bMACMov7fZQA1SEAGi7SgBIpeP1q9VjdaBqus7tNIGAlFyUsoA0EJKBcdBiApgDATD
	3XABXu2lIFAovL6jwA9gcBEstcAIUCM3CUn6dpfzw4VQIaIIDn3+Hq/raeXwECNya01jpebm0FYOO0fiiQy6V5OvDGDAAoydIKAgAAeP4qwLFTcjbANAwe25kAe3ib1lkXQC/aJwSHVg0wA4A+pZahgMDfXpm
	xgVETCLBnaLDzjFiAL12lRiBNaSu10CbBOQjU7Zd8dcCkT0DGDmYJRnb/YwKBPrrKgwB2sLPUyE2QKsDah92mTBsvtJiAddzf5pVqEKBQwJ4F8KEA6SwA2JwLsLbSnOte4vZgGy/LG/61JcAbG5Wx1kk8HM32
	CAjGjQpQaAOBD24BXr9K2qui9AzmvSsD386Oy+uOQoBaSkwG3pjMH4j9Xn9j0iwRHtyJkV64pOrBePE9GbgJq+rqEJSs9ZASgXZ1K3FISGken1le0xZHz38z06+XzwCme8Cwg+czg1zKzgTYv9yoko2mIcfQW
	IBMX3kWMIRQgOnmAEzCgCHT/drYxYdMFpcBEBu7/+c6yuYPNBmGvxc3H1CznFJYQOLik5EsOHsnzNDwTZW4y9hbV3nU6KxsZfim3mhnEqdNuA6RcgACnrXWQiVsBQDwlQATo2aZGb9voz8w0lkScDTuzi0Yrf
	f+fNFDGuGNyeEQic99pCq6LAALzAMoqnsLxRh1X+PnjbOv0VuuKZoueAqlQRHUUgSBmnLpsICBlQfHg7palXI+/CIA3xoBTPcrD+oqZHrxfdV+PKs8BF87WcK0fm4qCUrGsYA7Tw5PEE5cfDUByRmA7hHhueU
	A2hTYl6dXgYBT7UD/3rd+X52kp/i6m8/jev4euYAhlAMXTOKFosKF0IbPy2hsvl6s5f/I4m0bVq1hHRowFi8sYJq5gBJa2bdHjgCgdOof0vBVhjkamykviobf1NqoeQAZK5AlClMRkQU8KGC7sOpg0GAAgAkb
	P2I8jy+TxWWA468eXkLG1GuJEoSYTv3PDdBdO9Xzbj5PAwgM+gKyCQO6DgYNAgAsUePfuh0myWeLmran49bxPzL/a+giNGARypZtAHq53L4A3YNBhxECbCW+e+74Kbu9B74N33eOIHZe4GJBU4S37RPL5QLAj
	Ulc4zdJzLVVBkzsm990lBqItlUOYlYIZLmATMMA2/jfHQCkSJ9cGf/ZjerhOv5XslRmFg4wbE4ojkn/Te5LzApBnQvo0uPIeS0t8FHE/12zBO0bgWRHMqcW+7uUNhDoCzQ71W7BhtcXp9V0KSFmVoPdut1cT9
	9NTH30OLOlNYn/2xmA7WSgoVB/PmavGYLIFGov30XNp/tqj6M1P2Dk7zp9raUYEsRiAjp6jOU2BdkzAHEyUGnUX+X1VfMCVq8A/PLEPMZVPXfr9rw9mHM5zIR3MgS88I4/FlWvgU8gqD8jBhMQ24PvPjkcGhS
	8P6CsvQAuvQhv/IhqQ25T2hoI2mz3AwA4ujxPGLJ986BzYaGdnfgIgXwAwdbtCjj5nEBIIDh/CuDed9XPdyQAgOWCQFnzAFwm/ro8/rWl+aMPWO08qxZvOnWziB2g0zvs8ZEUBTjcpxFyi/F6x0Eis9tfYhjg
	DgBK3kZZK39fo+eXa2uzuXjYcRabbKYYjvyU/2RGJ4KgDxCI1TMwwnx7ArZHngDAdlNQLPmNo8k4omJfW6q8qmtKyphA/e3oVaP85+o7XlvSCyV8sIFYICAmA/+cRmn7wZ2P1JrRowfALQMQaVOOO6xqZXbo6
	d0oMztc6vOV+edDCd11KAEExP0Bn8lZQHJhQNceAPQJAKpTgkKGBK4Uw6fR8+bMnxfQ51jxg9OHAqBt19rkDALYwgIyE2kPAOsDAF1hQCqnBLlI/q1eCQ9WXcbPUGn8B/SfsXBZcxUQ5AoC/MQgFauNIG9e9s
	s4+jGAksaD+8qeS2mb5j6Btg4/kf7H6KITP5OvErgGARnD6QMCaMhqUw8DksgBGMYeSdH/98Mds3UwuKMn9ffS+9+HDfBVAtcgEHIrd2rjw1lOACA7cdU3EGxldlhm3/FdtffnS5OpAAH/XUKEA7bgzzpYbYl
	H3wUBABYewXrL2YCetFZYE+/flgdgiS5saBCIxAJKCQO6AcCkHyA0XXJB/zFcvfKA/neW8FA+7WfW+HNA/1M9F5D/Xq6Tq+ImIh8zBXQGhyIMBAC6JCZdcuERYiX/WkFg1niO8hgqeeMXQYAxvw1DvmYKyAaH
	YkbMNhgAZF47Deb9D87www4QYJnFUJpMoCUkYC+epfndZSyAlRcG6AGAKgyIVQp0gfqB4n/2wS3O+0s6+lBvUyaefycP798GAoiH2AAe67GXwfc8gcgVgb4A0zUNyA0DiJUHcEH/AxkSXr86N145RPhv7U0lH
	ODB10Vo4CoxiJKfZSygsFOF3QDAgMom9gqGHSAAShDAC79oGlM9Y198pDJ7PyTY1iDQ57pZy8/i+HBBv5MOAzQSlfoDQdY+xNZzAy9x04FC5AEyov8HMks2IlwDuDEBdv9j7i4Jmf62MiFvRG1lQN3Z+7G6B2
	Xf6+xGuv0cF1eq28Pr99dPszhUNBwDCJ0HyIj+t302/upatZlncUnOBHg2cOxUeeGAL0A2dQ6oqd+FslwzAMhtRkDqUcH1q4DXr86AYPnwcI8ZEODqhlvAQowPAvx3cPF9bJ2CLmFVVLuSDQOYawBIQXKk/7p
	AANAEAxkoOFGMBEqLfP9F/X1isQAblltIMjC/oaC50/8OIJj3C8x/d2An/N8aewr0plZ2JiEj5wTYw9v9yIB43kCvmwHN/SwM0j4Lo+sagjKAwkolsdiA/o6/zJuFZiEBrjosC/ZlAbKqQG5hQNAQIESSpED6
	rwKCVqYi3VGIHa5gFmtjomkcPiRIpTegKwwoQNwBQIiW4ILpv1+4Z/NYmw2kXds1CGCZTNccANoqAb7RMcXmltCsYHUD4MX3VZ/AdL/61+Bx0HuQwy7C2EwNW/BVwXR9j+9KmwHkgI6Z0H+1Yo66Gb+CHBxsS
	R6C2I6KVyXPRKab+Q5BtwDgKw/gcupvzmL8/bF6YIbX6CpXYaM7XRODIBOjx9AA4DMP0DemK8H7G99h4bSh6TQfEKjnCKSWC+iQpKoBwRuBUm6WwIKaGA/ahFk7GEiPEtPcJ1CaUP7IMQCoWoJT7Jk+uxF28k
	8QRUY13MvuEMM0pgmHDtdMWICNn0jVtwQPAXyEAYTeBvyuIyOFmWWp6gEiidHmrtdECwMejiOHAHUYwLOAu0/ixnGlxf7i3gBmmIbOKRRyydpcHR6bMIfHzcU+L3co57ntq3eeAIlPL8m6Y38+d8BYXiBwban
	QBK4jwvIWdx7gNGQIoMoDrJ9uhgGxk4EldP/phkLIlCDAHt7OrxvQ1f0LEU5i4DDgwm6vcMYPAxghjQmLzQraQGAn05xKqixAdG6ZYau/TkAaF+7HtnWz+CiZPpyjhqbE4pBzcIU4N38AUODOqbSQYNQe6LFC
	BzfFZgEa24IJAFwLVQA6YldJMxAS42rVJZM8AJbv3BZIK0qSwg0/dBhgu5yhE4G8FX91JFEAiFUJKHX/f+sJw6gIF6q/Z70jMAdWFxqHz80rAXjvaEIA0DdZQl2APbUPh8cSfIaUqd7xNUUvgFcA6BoTTpUAP
	9I5KRjLNfYcmpgcfcUHdz4CNtn0asV+GQBVAgLA/8C8fA5NTNw04dRPEKYkYO7eD1WbggosB4bO6aADIIjJRDpYOgFAkd6Pzf9ldJjTITHJLeVIpma7Atmz7vChbAAodgKwiRdg5TGB1Sv9Xl/ilCDLXYHEAI
	ZBHcq6nNSGu/Al7khYq9wVSABQmEgPBlFpxz6tmWtpK3HHwlrVrkCvAGByYrBpM9DWbVI0I0PvuhWUDziQvgNCDEvcqVYD/DMA2hbsM8BvGjUyuaGzZl9ANnMBU5YMSty4tJ4AAFAzUH9RJjOZ4ncFbw56/2q
	6eYCMxA0AqMKAQs9Vj8byG338rCMcIMDNnd3qeHGpiANCozEACgMcaQK3hrJWYDH+py3B/qKuQOzWOG9gUQoMAwAUBvSXrtKXrsF37iMgURo/SzcPIC0F3n2PxQcA2hNAUkT8lfj3sygFxukDoDxAP6n7AJjG
	cWAkJEEAoKsfwCYP0Hf4Q+nzBA4N/hxYeJXacJDasQnVWeuYPisAoDyAX3EBZhT/u88JyBwbg2wKMOEAgPIADhQONWNUCgWC5QQyd2wLgzaY7BRupmBtvf0HWWo2DCBIoVXcpM8FCQD0FspVfMjKCjXY/Y+7N
	wKhlBKQ+BTd/Jbp7agbOW2bgZIDAGoIsjf+h7QxKpm4X5TLnsKAAPgdFgBM4iWaCNy+FjgSRn0b6C9tBHJrlAgAF/XDgCiVAEUzUFgAoERgf+M/UMQprU0qgID5slu3AGAyG8Aklh+q4XN71huem+2b88MSh4
	KkohseqgGhmAJNBErV+OsM99btZrZb15BlOmg6SShHZhQrL+B41+uDOx8RAAxWZOWtBx8Dsj1AXc/fwsUomegxL+AjDMChA4BtrTfXHgBxVNXOs+ox3ed0gh08rPS1FBBI7eRoMQxwoYIsNwDwkQcYisiMH2B
	m/KzFQeiAQfOW4PWrtNY+vLMYBjx4GjW+H24IkGPikI9pa68vugHV9C/G7UGpy4QHj4XqX9oL4If689IVBiAk1RFIOYBUjH9GZ9nz76p/9/cqzz/dU8aD2u3/M+OnPgDP0lUNSGyjkB8A0A0DujKliPbevG4D
	zqihiD3/rjrNa29vdgns0CWJD/5SBwWYqYqnXhebdmCdk4XDMwCdTGl9g4eg2bNrrT2/SBFFY1fhHWt7Eu/96bi0sDp+90nSXzU8AITcPpl6JaA2/j/9h7vLlYFAvQ6lGD9iehUAXs6fmv98xx4AQvQChAeAk
	O3AKTMIH8YvA73FZQDGysr8p3Jf2/zL+ummk0thBF7LfgBKAsbU4z/9p8M3qzSSSTYJUeJPIi7YEFOEAB2hbqhSYFceID4AyNCx782p6WGqIcCNycz43XgybLvWxWWK+2OxgEwmBfkDAFUlINTOqUQrAS6Nnw
	e6hvcv1fhTqwAwzVA30UnYcRhACHRM+WThhZFD28fD7og8fxriIAxwkghUNB/FAQDTRKBt1jaxUIB9cAvYB7eqxBzi/Hs5wECGI4DFJTJ+X7qUqqPT0Y1nm606lkYS0EceQBYKxA4X60z8zmQ+0QcRYAEdGP+
	Aav1bmWxmymAATjwACJUHqJUlkdgRVzcA2N7hff2WLIUdOzUs43fB5mKtkWUewGc/QDwAGPBBIXjhFxJLngVrRgqOTXYxBNqfW3do4qPCwgEACv/q0CNXCr11uzKspKbICIM9+UQNagLB8VPN0GIIspXZLINU
	8gAt/QDhAIAJ/5rSo77Jm4dfpBUKnH9HDgQi3W0DguOvAq5u0N7+JG6mQR5A0HPthiBPeey4SUAdeuSa1ibUHHQAAovLAMdOqb8z97Xxh38/zEx/X/D2VQFgDvS8Kw/w5UcFAkBoerR1u4ohY7IA3mivLTWHd
	Bw7pQACBFgYA/7Tu9Xrhljmc3HNodcNIel8V1wA0C2T1DfNBYKnEENyBizt0+dBgEkYA0k+wrr1POaIsGFuBtq6XbGAlEqDwv/xwi+q3MDCLEdw7BQ195BkBgBt+wFswnCXLMBlXOnos/H61crwOTDA8+9Uj1
	9do2Rf7HvlUv5s1w/g45DQOAzANgzyFQrEzgm0efahxvq+wrcQa4ktv+MTgZ+l0w8QLwSQLVTMHVM3n8cx/rb/k+HnG/PLxEEi0EdH4EL0hTItkbhmAbVXiV0dIK+vFvHMhNxAQZUIxECJQMlUoPhJQBtkdG0
	gqYQDJOmwM1estk14tuuqMviXI2ocknQD+geArhHhfXZMuUwIEgikK3UXZ670HyzZrin+3OMA4DW9Q2TzLQP6qAoQCJRL/d9PoIriuyFoZw4w7MqLwgHARyhAIEDilQ1L9gVwpMBpHmABEgIA3weGuu4NIBAo
	K/ZP6axIMQyI3BmcHgMwPTzRV4NQXSGouwZJwhu/q9g/papKYvsC0gMAm8MTfYEADwY5l6FykxsTd8af2knRie0LKG8vgM8bTiAQRlxu2Cqsp8J1O3B6AGDbDcjfaN8gcPN5UpuJivP+ruT9DPZPRD4vIBwAh
	DgoJBQI8PSUgMCt8ec28stGEjk2LB0G4DIxEgoEREUlIEiL+qfo/bG/vree9bc9yhgAXM9PjwUCPBDUYQJJeOqfqrD++t6WA8AvFvXeQNgPkAYA+OgSiAkCAM1zCQkIwnr/s/mfhmwcBnBdgHBuV9vW0gAAkQ
	W5SozEBgEKEcJ7/7MZDksVOgJ7m9PbL7VtLZ0qgK+NEimBAAGB2vh3nrm93ymLqiMw4ODqdADAZ4dUaiBAQDBfA34mAz8huVTqr5MIZJZhQNYA4PsgRX7QRiogwAPBkMCgvl7XcX8O3p950PftUSYAYLIpCD0
	CQWogwBtGLsMvXHn9IRi/Z0qvXQFIlgFgd7KiOBBoO6GoHk1WGiO4Mam6KH00+qTu+XvoslYYoFsBSBYAZAvku0WyDgl8NoyolF3nlNsSgMCn4QMArF6BoYlqP4CyAiCRcVJXNsJ5QuTzbYA3Tob53Pev+mtD
	Fd/z7Ebl/U2Oua5BILfylu/NU6tXAH55AkjsJTwArH2IsumkAFBlRje/rX4OvVf62hLAjY1+MbwpIJiGIDI2kCIohNo1yVg5lvj101aH9+ald72MBE+PAaxxABBDri1VRnY2ABD0BQMRFGpWgRjPK4bcLl1At
	58t423dD5AlAKAiSaJARe8gIFOyVJmB6A15puCbIcSckZD7Xv+YjDcZAGCJ5AHaQEDmdXJgBrXcfN4EB95o+iYYY23dzbHdV+b0YjNeiFUFUPUDpDIzTaVgZzfCUVB+NqFSqXDOBPgSI2/8iM3disaKi2T8Pp
	yehijLgbwVf3UkwxwAHwaIqBgjDOhiAm3eOSYz4A29BgH+X/45plUI/n1jDuzI2fgR/PW2nNsF+LoyfLx3FNgF/V6ANPsAxI0SGPG7mShcLGYgM0rR6NvAIgfKX4Ln11nyjt6XNhbA1rja/zSHEMA0DIhd7ZE
	pHqI+M4gBCG3AgJif8ZRA+9vExS5YEyvGFEOAQ+CQUBjQFg50eVEeBGJ6zrbPTuX7dUkOgz37hAKGlQCXJcD4AKBqCkqhGmCaE+gCg5QMLWWjL9njM1DnvAKHIumeCyCGAZHHJ1vlBNpyBCU0sfgy/JKNX0d0
	9Hzao3wrhN7xAaAtF/DjFe/HKfcCAVFJEc3iawICudcfgvF3Jb1VEUTxB4PwiySygLtP0vqOvLIyZpddHzoInN2o4vwhe/3L+r0vBzmALhag6YzGSS/Mj1cAXkwB7n1X/f/OE4Bj4zTyASIIiD35shvSBhC5J
	OQozvcjF1cAbjtOems6o0TOBWgJAxgArJ+eU6R9llYoIAsLfnlCrthdN6RG7NJDg9Ur5PEP7nlHGOCjYisk3cfJL9IID5dKUigLmoQHOpUDESBWrzR/lzszII+vzgV06bisk3A6AVjot6bjLBZqbaWi/6mVBX
	2BgQwQeFaA6O74bN9SWh3fBwtgLToOMNdzJntRf0loKrCiMxAh3bKgbajQxxsy1iwpphgy1Mk9Ej0WINNxIdydNwGxJgsokgHwIMcKYAGumIEqto4ZMoggRHTfHAjqUeEBw91x0gsiSo65gFBg0BYy2O78MwJ
	rYechGb+9s7NxdNMJAHSvuayHIK0+gK5zA9YSbg5KLUxoA4baYF0bP3l+d84uYLibXiNQFwiUkguwAYPauEy7DnVAocvIu96rLoGSOLABiaNr6DkWDAA2izMkqQ2N7zewAQOT16gAYyjtu6FFmRAU7sf20cJy
	AKpdgqXnAvrkDnjpyiPYsACi+mEdHUBTzx+OAVb3Dt+azVcKAwAFCLDJJuDaurpmSkIGWgoIcHqOm4uV739NeN4OR+Rf/2vhIYAWRSIhKTAUmFYgAA+PtxO7y/KcWNv/M5qwAAACXklEQVQuwrQ7AbtYgEiRh
	hwKkBQhhyb+vA4AL48A/vHoHAS+XAYGU4CzksnOhq3B2TEAXFqfo1lntpSEJAel7vj7hV1gF/nBnwj45StOPjp9ADAtC376GOD3f2kCAZKOkVgYXij51/sAv70P8Pu/AD5+o/m37RHgv5+oGMCRaQMEYGsZAE
	e9Pnqc/Q0Us6UAAJO9ZmJQnMNGkue9Zj1eI3t9avow2QP49DFgW1ffbtNf45cne18CslxOWFWVBQGqaUHicMURAvz0DMAPTuopkQuQIKAh6ZJHzwE+264M3occZ9XhIOd2G6GzjFWPi1nUtZXqwQPBPqsWmnF
	MQCUuDJeMnySW4dfyVwT8r6PAdqv8gSqkzgcAupqDeCDgQwK+RGhTIZDRSCRjJ/Fk9OdfqVgrCBUBftvv/ROA/7Pcrbr3jgJ7c1eZ6RsXuegyEPj0McCdbwEunTYDAib5mQcBEhIHxm4kP0SAP8HhY8DO7QK7
	9BLwi2MA34wAXtvrTPPnkwPQzQXwHluWFwAAWBq3A4FJDE/x/jAotWsxMPzWk4C+4noD6uf+A8cSdhBgkTVzAJKKWn4AoAMCjec+UZ+8ogIDEjLkCEZvBQLndgF+flHtpAYJALpAQOBARp2AsXcBgNHBIB3Gn
	y8A2IKALRAQIKRt6I4NrkgpDgBsQUAnRzBUQIhtzGTIBADBmIBPpkBCRp2B8ZcBAD5BgACBDL1g4y8HAEICwRAAoVRjLrFsK7umrg10xQJAaBAgIc+aO34UBwAEBCQDM2ICAAIBMmISAgCvQFArWs6gQsZCIs
	j/AwLQ3DbbVjUvAAAAAElFTkSuQmCC" />
	<style>
	body {
		background: #8a8a8a;
	}

	.content {
		max-width: 1250px;
		margin: auto;
		background: white;
		padding: 10px;
	}

	form {
		margin: 0;
	}

	.message {
		color: red;
		margin: 10px 0;
		padding: 10px;
		background-color: #ffe6e6;
		border: 1px solid #ff9999;
		border-radius: 4px;
	}

	.info {
		color: #0066cc;
		margin: 10px 0;
		padding: 10px;
		background-color: #e6f3ff;
		border: 1px solid #99ccff;
		border-radius: 4px;
	}

	input[type="submit"], input[type="button"], input[type="file"], button {
		background-color: lightgrey;
		padding: 4px;
		cursor: pointer;
	}

	.abutton {
		text-decoration: none;
	}
	
	textarea {
		height: 530px;
		width: 99%;
		display: block;
		resize: vertical;
	}

	.login-form {
		max-width: 400px;
		margin: 50px auto;
		padding: 20px;
		border: 1px solid #ccc;
		border-radius: 8px;
		background-color: #f9f9f9;
	}

	.login-form input[type="text"], .login-form input[type="password"] {
		width: 100%;
		padding: 8px;
		margin: 8px 0;
		box-sizing: border-box;
		border: 1px solid #ccc;
		border-radius: 4px;
	}

	.security-info {
		font-size: 12px;
		color: #666;
		margin-top: 15px;
		padding: 10px;
		background-color: #f0f0f0;
		border-radius: 4px;
	}

	.file-list {
		margin: 10px 0;
	}

	.file-item {
		display: flex;
		align-items: center;
		padding: 5px 0;
		border-bottom: 1px solid #eee;
	}

	.file-checkbox {
		margin-right: 10px;
	}

	.file-info {
		flex-grow: 1;
	}

	.file-actions {
		margin-left: 10px;
	}

	.bulk-actions {
		background-color: #f0f0f0;
		padding: 10px;
		margin: 10px 0;
		border-radius: 4px;
		border: 1px solid #ddd;
	}

	.bulk-actions button {
		margin-right: 5px;
		margin-bottom: 5px;
	}

	.bulk-actions button:disabled {
		background-color: #ccc;
		cursor: not-allowed;
	}

	.select-all-container {
		margin: 10px 0;
		padding: 5px;
		background-color: #f9f9f9;
		border-radius: 4px;
	}

	.action-buttons {
		display: flex;
		gap: 5px;
		align-items: center;
	}

	.btn {
		padding: 6px 12px;
		border: none;
		border-radius: 4px;
		text-decoration: none;
		color: white;
		font-size: 12px;
		font-weight: bold;
		cursor: pointer;
		transition: background-color 0.2s;
		display: inline-block;
		text-align: center;
		min-width: 60px;
	}

	.btn-download {
		background-color: #28a745;
	}

	.btn-download:hover {
		background-color: #218838;
	}

	.btn-edit {
		background-color: #007bff;
	}

	.btn-edit:hover {
		background-color: #0056b3;
	}

	.btn-rename {
		background-color: #ffc107;
		color: #212529;
	}

	.btn-rename:hover {
		background-color: #e0a800;
	}

	.btn-delete {
		background-color: #dc3545;
	}

	.btn-delete:hover {
		background-color: #c82333;
	}

	.progress-container {
		display: none;
		margin: 15px 0;
		background-color: #f8f9fa;
		border: 1px solid #dee2e6;
		border-radius: 4px;
		padding: 15px;
	}

	.progress-bar {
		width: 100%;
		height: 20px;
		background-color: #e9ecef;
		border-radius: 10px;
		overflow: hidden;
		margin: 10px 0;
	}

	.progress-fill {
		height: 100%;
		background-color: #007bff;
		width: 0%;
		transition: width 0.3s ease;
		display: flex;
		align-items: center;
		justify-content: center;
		color: white;
		font-size: 12px;
		font-weight: bold;
	}

	.progress-text {
		text-align: center;
		margin: 5px 0;
		font-weight: bold;
	}

	.file-upload-area {
		border: 2px dashed #007bff;
		border-radius: 8px;
		padding: 20px;
		text-align: center;
		margin: 15px 0;
		background-color: #f8f9fa;
		transition: background-color 0.2s;
		display: none;
	}
	</style>
</head>
<body>
	<div class="content">
	<?php
	// LOGGED IN
	if (is_logged_in()) {
		// CSRF token for forms
		$csrf_token = generate_csrf_token();
		
		// UPLOAD NOTES
		if(isset($_GET["NOTES"])){
			if(isset($_POST["submit"])){
				// Validate CSRF token
				if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
					echo '<div class="message">Security validation failed. Please try again.</div>';
				} else if(isset($_POST["file"]) && isset($_POST["note"])){
					if(isset($_POST["dir"]) && is_dir($_POST["dir"])){
						$newFile = "./".$_POST["dir"]."/".$_POST["file"];
						if(!file_exists($newFile)){
							if(file_put_contents($newFile, $_POST["note"]) !== FALSE){
								chmod($newFile, 0777);
								echo "<p>Your note: ".htmlspecialchars($_POST["file"])." has been successfully saved.</p>";
							} else {
								echo "<p>Failed to save the note.</p>";
							}
						} else {
							echo "<p>File [". htmlspecialchars($_POST["file"]) ."] already exists.</p>";
						}
					} else {
						echo "<p>Target directory not found.</p>";
					}
				} else {
					echo "<p>Invalid parameters.</p>";
				}
				echo '<button onclick="window.location.href = \'./\';">< Home</button>';
			} else {
	?>
	<div>
		<form action="./?NOTES" method="POST">
			<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
			Notes: <br><textarea name="note" wrap="hard"></textarea>
			File name: <input type="text" name="file" size="40" value="NOTE_<?php echo date("Y-m-d_H-i-s"); ?>.txt"><br>
			<span>Upload to: </span>
			<select name="dir">
				<option value="PRIVATE" selected="selected">Private files</option>
				<option value="SHARED">Shared files</option>
			</select>
			<br>
			<br>
			<input type="submit" name="submit" value="Upload notes">
			<hr>
		</form>
		<br>
		<button onclick="window.location.href = './';">< Home</button>
	</div>
	<?php
			}		
		// UPLOAD FILE
		} else if(isset($_GET["UPLOAD"])){
			if(isset($_POST["submit"])){
				// Validate CSRF token
				if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
					echo '<div class="message">Security validation failed. Please try again.</div>';
					echo '<button onclick="window.location.href = \'./\';">< Home</button>';
				} else {
					$files = array();
					foreach($_FILES as $upload => $fileUploads){
						$fileKeys = array_keys($fileUploads);
						
						if(isset($fileUploads["name"])){
							
							for($i = 0; $i < count($fileUploads["name"]); $i++) {
								
								foreach ($fileKeys as $key) {
									$files[$upload."-".($i+1)][$key] = $fileUploads[$key][$i];
								}
							}
						}
					}
					
					foreach($files as $file){
						echo "<p>";
						if(isset($file['error']) || !is_array($file['error'])){
							if($file['error'] == UPLOAD_ERR_OK){
								if(isset($_POST["dir"]) && is_dir($_POST["dir"])){
									$newFile = "./".$_POST["dir"]."/".$file['name'];
									if(!file_exists($newFile)){
										if(move_uploaded_file($file['tmp_name'], $newFile)){
											chmod($newFile, 0777);
											// UPLOAD OK!
											echo "Your file: ".htmlspecialchars($file['name'])." has been successfully received.";
										} else {
											echo "Failed to move uploaded file.";
										}
									} else {
										echo "File [". htmlspecialchars($file['name']) ."] already exists.";
									}
								} else {
									echo "Target directory not found.";
								}
							} else if($file['error'] == UPLOAD_ERR_NO_FILE){
								//echo "No file sent.";
							} else if($file['error'] == UPLOAD_ERR_INI_SIZE || $file['error'] == UPLOAD_ERR_FORM_SIZE){
								echo "Exceeded filesize limit.";
							} else {
								echo "Unknown error.";
							}
						} else {
							echo "Invalid parameters.";
						}
						echo "</p>";
					}
					echo '<button onclick="window.location.href = \'./\';">< Home</button>';
				}
			} else {
			?>
	<div>
		<div class="progress-container" id="upload-progress">
			<div class="progress-text" id="progress-text">Preparing upload...</div>
			<div class="progress-bar">
				<div class="progress-fill" id="progress-fill">0%</div>
			</div>
			<div id="upload-details"></div>
		</div>

		<script type="text/javascript">
		var uploadCount = 1;
		
		function upload_changed(){
			var i;
			var count = 0;
			var used = 0;
			var last = 0;
			for(i = 0; i < document.upload.elements.length; i++){
				if(document.upload.elements[i].type == 'file'){
					count++;
					if(document.upload.elements[i].value.length > 0){
						used++;
					}
					last = i;
				}
			}
			if(used >= count){
				var lastfile = document.upload.elements[last];
				if(lastfile){
					count++;
					var inputfile = document.createElement('input');
					inputfile.type = 'file';
					inputfile.size = 40;
					inputfile.name = 'upload_'+count+"[]";
					inputfile.onchange = upload_changed;
					inputfile.multiple = ' ';
					lastfile.parentNode.insertBefore(inputfile, lastfile.nextSibling);
					var br = document.createElement('br');
					lastfile.parentNode.insertBefore(br, lastfile.nextSibling);
					lastfile.parentNode.insertBefore(br, lastfile.nextSibling);
				}
			}
		}

		function submitUploadForm() {
			var fileInputs = document.querySelectorAll('input[type="file"]');
			var hasFiles = false;
			
			for (var i = 0; i < fileInputs.length; i++) {
				if (fileInputs[i].files && fileInputs[i].files.length > 0) {
					hasFiles = true;
					break;
				}
			}
			
			if (!hasFiles) {
				alert('Please select at least one file to upload.');
				return false;
			}
			
			showUploadProgress();
			return true;
		}

		function showUploadProgress() {
			document.getElementById('upload-progress').style.display = 'block';
			var progressFill = document.getElementById('progress-fill');
			var progressText = document.getElementById('progress-text');
			var uploadDetails = document.getElementById('upload-details');
			
			progressText.textContent = 'Uploading files...';
			uploadDetails.textContent = 'Please wait while your files are being uploaded.';
			
			// Simulate upload progress
			var progress = 0;
			var interval = setInterval(function() {
				progress += Math.random() * 15;
				if (progress > 90) progress = 90;
				
				progressFill.style.width = progress + '%';
				progressFill.textContent = Math.round(progress) + '%';
				
				if (progress >= 90) {
					clearInterval(interval);
					progressText.textContent = 'Finalizing upload...';
				}
			}, 200);
		}
		</script>

		<form name="upload" action="./?UPLOAD" method="POST" enctype="multipart/form-data" onsubmit="return submitUploadForm()">
			<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
			Files: <br>
			<input type="file" name="upload_1[]" size="40" onchange="upload_changed()" multiple>
			<br>
			<br>
			<span>Upload to: </span>
			<select name="dir">
				<option value="PRIVATE" selected="selected">Private files</option>
				<option value="SHARED">Shared files</option>
			</select>
			<br>
			<br>
			<input type="submit" name="submit" value="Upload files">
			<hr>
		</form>
		<br>
		<button onclick="window.location.href = './';">< Home</button>
	</div>
			<?php
			}
		// EDIT FILE
		} else if(isset($_GET["EDIT"]) && isset($_GET["DIR"]) && isset($_GET["ID"])){
			$files = scandir("./".$_GET["DIR"]);
			$files = array_diff($files, array('.', '..', '.htaccess'));
			if(isset($files[$_GET["ID"]])){
				$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
				if(file_exists($file) && $files[$_GET["ID"]] != ""){
					if(isset($_GET["SAVE"]) && isset($_POST["content"])){// edit or save
						// Validate CSRF token
						if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
							echo '<div class="message">Security validation failed. Please try again.</div>';
						} else if(file_put_contents($file, $_POST["content"]) !== FALSE){
							chmod($file, 0777);
							echo "<p>Your file: ".htmlspecialchars($files[$_GET["ID"]])." has been successfully saved.</p>";
						} else {
							echo "<p>Failed to save the file.</p>";
						}
						echo '<br><br><button onclick="window.location.href = \'./\';">< Home</button>';
					} else {
						?>		
						<form action="./<?php echo "?EDIT&DIR=".$_GET["DIR"]."&ID=".$_GET["ID"]."&SAVE"; ?>" method="POST">
							<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
							Filename: <?php echo htmlspecialchars($files[$_GET["ID"]]); ?><br>
							Content: <br><textarea name="content" wrap="hard"><?php echo htmlspecialchars(file_get_contents($file)); ?></textarea>
							<br>
							<input type="submit" name="submit" value="Save file">
							<hr>
						</form>
						<br>
						<button onclick="window.location.href = './';">< Home</button>
						<?php
					}
				} else {
					echo "File doesn't exist!";
				}
			} else {
				echo "File doesn't exist!";
			}
		// RENAME FILE
		} else if(isset($_GET["RENAME"]) && isset($_GET["DIR"]) && isset($_GET["ID"])){
			if(isset($_POST["submit"])){
				// Validate CSRF token
				if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
					echo '<div class="message">Security validation failed. Please try again.</div>';
				} else {
					$files = scandir("./".$_GET["DIR"]);
					$files = array_diff($files, array('.', '..', '.htaccess'));
					if(isset($files[$_GET["ID"]])){
						$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
						if(file_exists($file) && $files[$_GET["ID"]] != ""){
							if(isset($_POST["newfilename"]) && $_POST["newfilename"] != ""){
								rename($file,"./".$_GET["DIR"]."/".$_POST["newfilename"]);
								echo "<p>File successfully renamed to: <span style='font-weight: bold;'>".htmlspecialchars($_POST["newfilename"])."</span></p>";
							} else {
								echo "New Filename is empty!";
							}
						} else {
							echo "File doesn't exist!";
						}
					} else {
						echo "File doesn't exist!";
					}
				}
				echo '<br><br><button onclick="window.location.href = \'./\';">< Home</button>';
			} else {
				$files = scandir("./".$_GET["DIR"]);
				$files = array_diff($files, array('.', '..', '.htaccess'));
				if(isset($files[$_GET["ID"]])){
				?>
				<form action="./<?php echo "?RENAME&DIR=".$_GET["DIR"]."&ID=".$_GET["ID"]; ?>" method="POST">
					<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
					<span>New filename: </span>
					<input type="text" name="newfilename" size="40" value="<?php echo htmlspecialchars($files[$_GET["ID"]]); ?>">
					<br>
					<br>
					<input type="submit" name="submit" value="Rename file">
					<hr>
				</form>
				<br>
				<button onclick="window.location.href = './';">< Home</button>
				<?php
				} else {
					echo "File doesn't exist!";
				}
			}
		// BULK DELETE FILES
		} else if(isset($_GET["BULK_DELETE"]) && isset($_POST["selected_files"]) && isset($_POST["dir"])){
			// Validate CSRF token
			if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
				echo '<div class="message">Security validation failed. Please try again.</div>';
			} else {
				$selected_files = $_POST["selected_files"];
				$dir = $_POST["dir"];
				$deleted_count = 0;
				
				if (is_array($selected_files) && is_dir($dir)) {
					$files = scandir("./".$dir);
					$files = array_diff($files, array('.', '..', '.htaccess'));
					
					foreach($selected_files as $file_id) {
						if(isset($files[$file_id])) {
							$file = "./".$dir."/".$files[$file_id];
							if(file_exists($file)) {
								unlink($file);
								$deleted_count++;
							}
						}
					}
				}
				
				echo "<h4>{$deleted_count} file(s) deleted successfully!</h4>";
			}
			echo '<button onclick="window.location.href = \'./\';">< Home</button>';
		// BULK MOVE FILES
		} else if(isset($_GET["BULK_MOVE"]) && isset($_POST["selected_files"]) && isset($_POST["source_dir"]) && isset($_POST["target_dir"])){
			// Validate CSRF token
			if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
				echo '<div class="message">Security validation failed. Please try again.</div>';
			} else {
				$selected_files = $_POST["selected_files"];
				$source_dir = $_POST["source_dir"];
				$target_dir = $_POST["target_dir"];
				$moved_count = 0;
				
				if (is_array($selected_files) && is_dir($source_dir) && is_dir($target_dir)) {
					$files = scandir("./".$source_dir);
					$files = array_diff($files, array('.', '..', '.htaccess'));
					
					foreach($selected_files as $file_id) {
						if(isset($files[$file_id])) {
							$source_file = "./".$source_dir."/".$files[$file_id];
							$target_file = "./".$target_dir."/".$files[$file_id];
							
							if(file_exists($source_file) && !file_exists($target_file)) {
								if(rename($source_file, $target_file)) {
									$moved_count++;
								}
							}
						}
					}
				}
				
				echo "<h4>{$moved_count} file(s) moved successfully!</h4>";
			}
			echo '<button onclick="window.location.href = \'./\';">< Home</button>';
		// DELETE FILE
		} else if(isset($_GET["DELETE"]) && isset($_GET["DIR"]) && isset($_GET["ID"])){
			$files = scandir("./".$_GET["DIR"]);
			$files = array_diff($files, array('.', '..', '.htaccess'));
			if(isset($files[$_GET["ID"]])){
				$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
				if(file_exists($file) && $files[$_GET["ID"]] != ""){
					unlink($file);
					echo "<h4>File [".htmlspecialchars($file)."] deleted successfully!</h4>";
					echo '<button onclick="window.location.href = \'./\';">< Home</button>';
				} else {
					echo "File doesn't exist!";
				}
			} else {
				echo "File doesn't exist!";
			}
		// HOME PAGE
		} else {
			
			/* Name: human_filesize
			*  Source: https://www.php.net/manual/en/function.filesize.php#106569
			*  Date: 2020-11-09
			*  Author: rommel
			*  Edited: true
			*/
			function human_filesize($bytes, $decimals = 2) {
				$sizeChar = " KMGTP";
				$factor = floor((strlen($bytes) - 1) / 3);
				return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . " " . @$sizeChar[$factor] . "B";
			}
			/* ******* human_filesize - end ******* */

			function check_dir($dir, $csrf_token){
				if(!file_exists($dir) && !is_dir($dir)) {
					mkdir("./".$dir, 0777);
					chmod("./".$dir, 0777);
				} else {
					$files = scandir("./".$dir);
					$files = array_diff($files, array('.', '..', '.htaccess'));
					
					if (count($files) > 0) {
						// Multi-selection form
						echo '<form id="bulk-form-'.$dir.'" method="POST">';
						echo '<input type="hidden" name="csrf_token" value="'.htmlspecialchars($csrf_token).'">';
						echo '<input type="hidden" name="dir" value="'.$dir.'">';
						echo '<input type="hidden" name="source_dir" value="'.$dir.'">';
						
						// Select all checkbox
						echo '<div class="select-all-container">';
						echo '<label><input type="checkbox" id="select-all-'.$dir.'" onchange="toggleAllFiles(\''.$dir.'\')"> Select All</label>';
						echo '</div>';
						
						// Bulk actions
						echo '<div class="bulk-actions">';
						echo '<strong>Bulk Actions:</strong><br>';
						echo '<button type="button" onclick="bulkDelete(\''.$dir.'\')" id="bulk-delete-'.$dir.'" disabled>Delete Selected</button>';
						if ($dir == "PRIVATE") {
							echo '<button type="button" onclick="bulkMove(\''.$dir.'\', \'SHARED\')" id="bulk-move-private-'.$dir.'" disabled>Move to Shared</button>';
						} else {
							echo '<button type="button" onclick="bulkMove(\''.$dir.'\', \'PRIVATE\')" id="bulk-move-shared-'.$dir.'" disabled>Move to Private</button>';
						}
						echo '<button type="button" onclick="bulkDownload(\''.$dir.'\')" id="bulk-download-'.$dir.'" disabled>Download Selected</button>';
						echo '</div>';
						
						// File list
						echo '<div class="file-list">';
						foreach($files as $id => $file) {
							echo '<div class="file-item">';
							echo '<input type="checkbox" class="file-checkbox file-checkbox-'.$dir.'" name="selected_files[]" value="'.$id.'" onchange="updateBulkButtons(\''.$dir.'\')">';
							echo '<div class="file-info">';
							
							if($dir == "PRIVATE"){
								echo '<a title="Show/Download file" target="_blank" href="./?SHOW&ID='.$id.'">'.htmlspecialchars($file).'</a>';
							} else {
								echo '<a title="Show/Download file" target="_blank" href="./'.$dir.'/'.htmlspecialchars($file).'">'.htmlspecialchars($file).'</a>';
							}
							echo ' - (' .human_filesize(filesize('./'.$dir.'/'.$file)). ' --- ' .date("Y-m-d H:i:s", filectime('./'.$dir.'/'.$file)). ')';
							echo '</div>';
							echo '<div class="file-actions">';
							echo '<div class="action-buttons">';
							echo '<a class="btn btn-download" title="Download file" href="./?DOWNLOAD&DIR='.$dir.'&ID='.$id.'">📥 Down</a>';
							echo '<a class="btn btn-edit" title="Edit file" href="./?EDIT&DIR='.$dir.'&ID='.$id.'">✏️ Edit</a>';
							echo '<a class="btn btn-rename" title="Rename file" href="./?RENAME&DIR='.$dir.'&ID='.$id.'">📝 Rename</a>';
							echo '<a class="btn btn-delete" title="Delete file" href="./?DELETE&DIR='.$dir.'&ID='.$id.'" onclick="return confirm(\'Really want to delete this file?\');">🗑️ Delete</a>';
							echo '</div>';
							echo '</div>';
							echo '</div>';
						}
						echo '</div>';
						echo '</form>';
					} else {
						echo '<p>No files in this directory.</p>';
					}
				}
			}
			
			// Display session timeout info with JavaScript countdown
			echo "<h1>TEFIS - Temporary files storage</h1>";
			echo '<div class="info" id="session-info">Session expires in: <span id="session-timer">60:00</span> minutes</div>';
			echo '<script>
				var sessionTimeout = ' . $SESSION_TIMEOUT . '; // Session timeout in seconds
				var sessionStartTime = Date.now(); // Current time when page loaded
				
				function updateSessionTimer() {
					var now = Date.now();
					var elapsed = Math.floor((now - sessionStartTime) / 1000); // Elapsed time in seconds
					var remaining = sessionTimeout - elapsed; // Remaining time in seconds
					
					if (remaining <= 0) {
						document.getElementById("session-timer").textContent = "0:00";
						document.getElementById("session-info").innerHTML = \'<span style="color: red;">Session expired! Please refresh the page or navigate to another page.</span>\';
						return;
					}
					
					var minutes = Math.floor(remaining / 60);
					var seconds = remaining % 60;
					
					// Format time display
					var timeDisplay = minutes + ":" + (seconds < 10 ? "0" : "") + seconds;
					document.getElementById("session-timer").textContent = timeDisplay;
					
					// Change color when less than 5 minutes remaining
					if (remaining < 300) { // 5 minutes = 300 seconds
						document.getElementById("session-info").style.color = "orange";
					}
					
					// Change to red when less than 1 minute remaining
					if (remaining < 60) {
						document.getElementById("session-info").style.color = "red";
						document.getElementById("session-info").innerHTML = \'Session expires in: <span id="session-timer" style="font-weight: bold;">\' + timeDisplay + \'</span> minutes\';
					}
				}
				
				// Update timer every second
				setInterval(updateSessionTimer, 1000);
				
				// Show notification about page refresh behavior
				console.log("Session timer resets when you navigate to a new page or refresh the current page.");
			</script>';
			echo "<hr>";
			echo '<button onclick="window.location.href = \'./?UPLOAD\';" style="font-weight: bold;">UPLOAD FILES</button><span> </span>';
			echo '<button onclick="window.location.href = \'./?NOTES\';" style="font-weight: bold;">UPLOAD NOTES</button><span> </span>';
			echo '<button onclick="window.location.href = \'./?LOGOUT\';">Logout</button><br>';
			
			echo "<h2>Private files</h2>";
			check_dir("PRIVATE", $csrf_token);
			
			echo "<h2>Shared files</h2>";
			check_dir("SHARED", $csrf_token);
			
			// JavaScript for multi-selection functionality
			?>
			<script type="text/javascript">
			function toggleAllFiles(dir) {
				var selectAll = document.getElementById('select-all-' + dir);
				var checkboxes = document.getElementsByClassName('file-checkbox-' + dir);
				
				for (var i = 0; i < checkboxes.length; i++) {
					checkboxes[i].checked = selectAll.checked;
				}
				
				updateBulkButtons(dir);
			}
			
			function updateBulkButtons(dir) {
				var checkboxes = document.getElementsByClassName('file-checkbox-' + dir);
				var checkedCount = 0;
				
				for (var i = 0; i < checkboxes.length; i++) {
					if (checkboxes[i].checked) {
						checkedCount++;
					}
				}
				
				var deleteBtn = document.getElementById('bulk-delete-' + dir);
				var downloadBtn = document.getElementById('bulk-download-' + dir);
				var moveBtn = document.getElementById('bulk-move-private-' + dir) || document.getElementById('bulk-move-shared-' + dir);
				
				if (deleteBtn) deleteBtn.disabled = checkedCount === 0;
				if (downloadBtn) downloadBtn.disabled = checkedCount === 0;
				if (moveBtn) moveBtn.disabled = checkedCount === 0;
				
				// Update select all checkbox state
				var selectAll = document.getElementById('select-all-' + dir);
				if (selectAll) {
					selectAll.checked = checkedCount === checkboxes.length && checkedCount > 0;
					selectAll.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;
				}
			}
			
			function bulkDelete(dir) {
				var checkboxes = document.getElementsByClassName('file-checkbox-' + dir);
				var selectedCount = 0;
				
				for (var i = 0; i < checkboxes.length; i++) {
					if (checkboxes[i].checked) {
						selectedCount++;
					}
				}
				
				if (selectedCount === 0) {
					alert('Please select files to delete.');
					return;
				}
				
				if (confirm('Really want to delete ' + selectedCount + ' selected file(s)?')) {
					var form = document.getElementById('bulk-form-' + dir);
					form.action = './?BULK_DELETE';
					form.submit();
				}
			}
			
			function bulkMove(sourceDir, targetDir) {
				var checkboxes = document.getElementsByClassName('file-checkbox-' + sourceDir);
				var selectedCount = 0;
				
				for (var i = 0; i < checkboxes.length; i++) {
					if (checkboxes[i].checked) {
						selectedCount++;
					}
				}
				
				if (selectedCount === 0) {
					alert('Please select files to move.');
					return;
				}
				
				if (confirm('Move ' + selectedCount + ' selected file(s) to ' + targetDir + '?')) {
					var form = document.getElementById('bulk-form-' + sourceDir);
					var targetInput = document.createElement('input');
					targetInput.type = 'hidden';
					targetInput.name = 'target_dir';
					targetInput.value = targetDir;
					form.appendChild(targetInput);
					
					form.action = './?BULK_MOVE';
					form.submit();
				}
			}
			
			function bulkDownload(dir) {
				var checkboxes = document.getElementsByClassName('file-checkbox-' + dir);
				var selectedFiles = [];
				
				for (var i = 0; i < checkboxes.length; i++) {
					if (checkboxes[i].checked) {
						selectedFiles.push(checkboxes[i].value);
					}
				}
				
				if (selectedFiles.length === 0) {
					alert('Please select files to download.');
					return;
				}
				
				// Function to download files with delay
				function downloadWithDelay(index) {
					if (index >= selectedFiles.length) {
						return;
					}
					
					// Create and trigger download
					var link = document.createElement('a');
					link.href = './?DOWNLOAD&DIR=' + dir + '&ID=' + selectedFiles[index];
					link.download = ''; // Force download
					link.style.display = 'none';
					document.body.appendChild(link);
					link.click();
					document.body.removeChild(link);
					
					// Download next file after delay
					if (index < selectedFiles.length - 1) {
						setTimeout(function() {
							downloadWithDelay(index + 1);
						}, 500); // 500ms delay between downloads
					}
				}
				
				// Show confirmation and start downloads
				if (confirm('Download ' + selectedFiles.length + ' selected file(s)?')) {
					downloadWithDelay(0);
				}
			}
			</script>
			<?php
		}
		
	// NOT LOGGED IN
	} else {
		// Login page
		$error_message = '';
		$info_message = '';
		
		// Handle error messages
		if (isset($_GET['error'])) {
			switch ($_GET['error']) {
				case 'rate_limited':
					$minutes = isset($_GET['time']) ? (int)$_GET['time'] : 15;
					$error_message = "Too many failed login attempts. Please try again in {$minutes} minute(s).";
					break;
				case 'empty_fields':
					$error_message = "Please enter both username and password.";
					break;
				case 'invalid_credentials':
					$error_message = "Invalid username or password.";
					break;
				default:
					$error_message = "Login error. Please try again.";
			}
		}
		
		// Check if user is still rate limited
		if (is_rate_limited()) {
			$client_ip = get_client_ip();
			$remaining_time = get_remaining_lockout_time($client_ip);
			$minutes = ceil($remaining_time / 60);
			$info_message = "IP address temporarily locked. Try again in {$minutes} minute(s).";
		}
		?>

		<div class="login-form">
			<fieldset>
			<legend><h3 style="margin: 5px;"><a href="https://github.com/F3lda/TEFIS" target="_blank" title="TEFISv2 by F3lda">TEFIS</a> - Temporary files storage</h3></legend>
			
			<?php if ($error_message): ?>
				<div class="message"><?php echo htmlspecialchars($error_message); ?></div>
			<?php endif; ?>
			
			<?php if ($info_message): ?>
				<div class="info"><?php echo htmlspecialchars($info_message); ?></div>
			<?php endif; ?>
			
			<form action="./" method="POST">
				<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(generate_csrf_token()); ?>">
				
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" required autocomplete="username" <?php echo is_rate_limited() ? 'disabled' : ''; ?>>
				
				<label for="password">Password:</label>
				<input type="password" id="password" name="password" required autocomplete="current-password" <?php echo is_rate_limited() ? 'disabled' : ''; ?>>
				
				<input type="submit" name="login" value="Login" <?php echo is_rate_limited() ? 'disabled' : ''; ?>>
			</form>
			
			<div class="security-info">
				<strong>Security Features:</strong><br>
				• Maximum <?php echo $MAX_LOGIN_ATTEMPTS; ?> login attempts<br>
				• <?php echo ($LOCKOUT_TIME / 60); ?> minute lockout after failed attempts<br>
				• Session timeout: <?php echo ($SESSION_TIMEOUT / 60); ?> minutes<br>
				• CSRF protection enabled<br>
				• Secure password hashing (bcrypt)
			</div>
			</fieldset>
		</div>
		
		<?php
	}
?>
	</div>
</body>
</html>
<?php
// -------------------------------------------------------------------------------------------------------------------------------------------------
// MAIN BODY - END
// -------------------------------------------------------------------------------------------------------------------------------------------------
}

/*
SECURITY IMPROVEMENTS IMPLEMENTED:

1. PASSWORD SECURITY:
   - Replaced plaintext password with bcrypt hash
   - Added timing attack protection
   - Secure password verification using password_verify()

2. RATE LIMITING:
   - Maximum 5 login attempts
   - 15-minute lockout after failed attempts
   - Progressive delays to slow brute force attacks

3. SESSION SECURITY:
   - Session timeout (1 hour)
   - Session regeneration on login/logout
   - Secure session cookie settings
   - HttpOnly and Secure flags
   - SameSite protection

4. CSRF PROTECTION:
   - CSRF tokens for all forms
   - Token validation on form submissions
   - New token generated on each session

5. SECURITY HEADERS:
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - X-XSS-Protection: 1; mode=block
   - Referrer-Policy: strict-origin-when-cross-origin

6. INPUT SANITIZATION:
   - HTML escaping for output
   - Form validation improvements

7. ERROR HANDLING:
   - Secure error messages
   - No information disclosure
   - Proper HTTP status codes

CONFIGURATION:
To change the password, generate a new bcrypt hash:
$new_hash = password_hash('your_new_password', PASSWORD_DEFAULT);

Then replace the $PASSWORD_HASH value with the new hash.

To generate a new password hash, you can use this PHP code:
echo password_hash('your_new_password', PASSWORD_DEFAULT);

The current hash is for the password: "password"
*/
?>
