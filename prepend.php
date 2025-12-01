<?php
// Lightweight country-based CAPTCHA gate for auto_prepend_file

if (php_sapi_name() === 'cli') {
    return;
}

$config = require __DIR__ . '/config.php';

function guard_get_client_ip()
{
    $keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR');
    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            $value = trim($_SERVER[$key]);
            if ($key === 'HTTP_X_FORWARDED_FOR' && strpos($value, ',') !== false) {
                $parts = explode(',', $value);
                $value = trim($parts[0]);
            }
            return $value;
        }
    }
    return '0.0.0.0';
}

function guard_state_file($config)
{
    $path = rtrim($config['storage_path'], '/');
    if (!is_dir($path)) {
        @mkdir($path, 0775, true);
    }
    return $path . '/state.json';
}

function guard_read_state($file)
{
    $default = array('bans' => array(), 'geo' => array(), 'attempts' => array());
    if (!file_exists($file)) {
        return $default;
    }
    $handle = @fopen($file, 'c+');
    if (!$handle) {
        return $default;
    }
    if (function_exists('flock')) {
        @flock($handle, LOCK_SH);
    }
    $content = stream_get_contents($handle);
    if (function_exists('flock')) {
        @flock($handle, LOCK_UN);
    }
    fclose($handle);
    $data = json_decode($content, true);
    if (!is_array($data)) {
        return $default;
    }
    foreach (array_keys($default) as $key) {
        if (!isset($data[$key]) || !is_array($data[$key])) {
            $data[$key] = array();
        }
    }
    return $data;
}

function guard_write_state($file, $state)
{
    $handle = @fopen($file, 'c+');
    if (!$handle) {
        return;
    }
    if (function_exists('flock')) {
        @flock($handle, LOCK_EX);
    }
    ftruncate($handle, 0);
    rewind($handle);
    fwrite($handle, json_encode($state));
    fflush($handle);
    if (function_exists('flock')) {
        @flock($handle, LOCK_UN);
    }
    fclose($handle);
}

function guard_purge(&$state, $config)
{
    $now = time();
    foreach (array('bans', 'geo', 'attempts') as $section) {
        foreach ($state[$section] as $ip => $item) {
            $ttl = isset($item['expires_at']) ? $item['expires_at'] : 0;
            if ($ttl > 0 && $ttl < $now) {
                unset($state[$section][$ip]);
            }
        }
    }
    if ($config['purge_probability'] > 0 && mt_rand() / mt_getrandmax() <= $config['purge_probability']) {
        guard_write_state(guard_state_file($config), $state);
    }
}

function guard_geo_lookup($ip, &$state, $config)
{
    $now = time();
    if (isset($state['geo'][$ip]) && isset($state['geo'][$ip]['country']) && isset($state['geo'][$ip]['expires_at']) && $state['geo'][$ip]['expires_at'] > $now) {
        return $state['geo'][$ip]['country'];
    }
    $endpoint = sprintf($config['geo_endpoint'], urlencode($ip));
    $response = false;
    if (function_exists('curl_init')) {
        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $response = curl_exec($ch);
        curl_close($ch);
    }
    if ($response === false) {
        $context = stream_context_create(array('http' => array('timeout' => 5)));
        $response = @file_get_contents($endpoint, false, $context);
    }
    $country = $response ? strtoupper(trim($response)) : '';
    if ($country !== '') {
        $state['geo'][$ip] = array(
            'country' => $country,
            'expires_at' => $now + $config['geo_cache_ttl'],
        );
        guard_write_state(guard_state_file($config), $state);
    }
    return $country;
}

function guard_show_ban($config)
{
    header('Content-Type: text/html; charset=utf-8');
    http_response_code(403);
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
    echo htmlspecialchars($config['strings']['banned_title'], ENT_QUOTES, 'UTF-8');
    echo '</title></head><body style="font-family: Arial, sans-serif; text-align: center; padding: 40px;">';
    echo '<h1>' . htmlspecialchars($config['strings']['banned_title'], ENT_QUOTES, 'UTF-8') . '</h1>';
    echo '<p>' . htmlspecialchars($config['strings']['banned_message'], ENT_QUOTES, 'UTF-8') . '</p>';
    echo '</body></html>';
    exit;
}

function guard_generate_captcha_code()
{
    $letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $code = '';
    for ($i = 0; $i < 5; $i++) {
        $code .= $letters[mt_rand(0, strlen($letters) - 1)];
    }
    return $code;
}

function guard_output_captcha_image($code)
{
    if (!function_exists('imagecreatetruecolor')) {
        header('Content-Type: text/plain');
        echo $code;
        exit;
    }
    $width = 160;
    $height = 60;
    $image = imagecreatetruecolor($width, $height);
    $bg = imagecolorallocate($image, 245, 245, 245);
    imagefilledrectangle($image, 0, 0, $width, $height, $bg);

    for ($i = 0; $i < 5; $i++) {
        $lineColor = imagecolorallocate($image, mt_rand(150, 220), mt_rand(150, 220), mt_rand(150, 220));
        imageline($image, mt_rand(0, $width), 0, mt_rand(0, $width), $height, $lineColor);
    }

    $textColor = imagecolorallocate($image, 60, 60, 60);
    $x = 20;
    for ($i = 0; $i < strlen($code); $i++) {
        imagestring($image, 5, $x, mt_rand(15, 25), $code[$i], $textColor);
        $x += 25;
    }

    header('Content-Type: image/png');
    imagepng($image);
    imagedestroy($image);
    exit;
}

function guard_render_captcha_form($config, $error)
{
    header('Content-Type: text/html; charset=utf-8');
    http_response_code(403);
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
    echo htmlspecialchars($config['strings']['captcha_title'], ENT_QUOTES, 'UTF-8');
    echo '</title></head><body style="font-family: Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; background: #f7f7f7;">';
    echo '<div style="background: white; padding: 20px 30px; border: 1px solid #ddd; box-shadow: 0 2px 6px rgba(0,0,0,0.06);">';
    echo '<h2 style="margin-top:0;">' . htmlspecialchars($config['strings']['captcha_title'], ENT_QUOTES, 'UTF-8') . '</h2>';
    if ($error) {
        echo '<p style="color: #c00;">' . htmlspecialchars($config['strings']['captcha_error'], ENT_QUOTES, 'UTF-8') . '</p>';
    }
    echo '<form method="post">';
    echo '<p><img src="?__captcha_image=1&amp;_ts=' . time() . '" alt="CAPTCHA"></p>';
    echo '<label>' . htmlspecialchars($config['strings']['captcha_label'], ENT_QUOTES, 'UTF-8') . '</label><br>';
    echo '<input type="text" name="__captcha_value" autocomplete="off" required style="padding:8px; width:160px; margin-top:6px;">';
    echo '<div style="margin-top:10px;"><button type="submit" style="padding:8px 14px;">' . htmlspecialchars($config['strings']['captcha_button'], ENT_QUOTES, 'UTF-8') . '</button></div>';
    echo '</form>';
    echo '</div></body></html>';
    exit;
}

function guard_session_start()
{
    if (session_status() === PHP_SESSION_NONE) {
        @session_start();
    }
}

$stateFile = guard_state_file($config);
$state = guard_read_state($stateFile);
guard_purge($state, $config);

$ip = guard_get_client_ip();
$now = time();

// Serve captcha image when requested
if (isset($_GET['__captcha_image'])) {
    guard_session_start();
    $code = guard_generate_captcha_code();
    $_SESSION['captcha_code'] = $code;
    $_SESSION['captcha_created_at'] = $now;
    guard_output_captcha_image($code);
}

// Check active bans
if (isset($state['bans'][$ip]) && isset($state['bans'][$ip]['expires_at']) && $state['bans'][$ip]['expires_at'] > $now) {
    guard_show_ban($config);
}

$country = guard_geo_lookup($ip, $state, $config);
if ($country && in_array($country, $config['allowed_countries'])) {
    return;
}

guard_session_start();
$verifiedKey = 'verified_' . $ip;

if (isset($_SESSION[$verifiedKey]) && $_SESSION[$verifiedKey] === true) {
    return;
}

$error = false;
if (isset($_POST['__captcha_value'])) {
    $input = strtoupper(trim($_POST['__captcha_value']));
    $expected = isset($_SESSION['captcha_code']) ? strtoupper($_SESSION['captcha_code']) : '';
    $created = isset($_SESSION['captcha_created_at']) ? (int) $_SESSION['captcha_created_at'] : 0;
    $expired = ($created > 0 && ($created + $config['captcha_ttl']) < $now);
    if ($expired) {
        $expected = '';
    }

    if ($expected !== '' && $expected === $input) {
        $_SESSION[$verifiedKey] = true;
        unset($state['attempts'][$ip]);
        guard_write_state($stateFile, $state);
        return;
    }

    $error = true;
    if (!isset($state['attempts'][$ip])) {
        $state['attempts'][$ip] = array('count' => 0, 'expires_at' => $now + $config['captcha_ttl']);
    }
    $state['attempts'][$ip]['count'] += 1;
    if ($state['attempts'][$ip]['count'] >= $config['failed_attempt_limit']) {
        $state['bans'][$ip] = array('expires_at' => $now + $config['ban_duration']);
        guard_write_state($stateFile, $state);
        guard_show_ban($config);
    }
    guard_write_state($stateFile, $state);
}

guard_render_captcha_form($config, $error);
