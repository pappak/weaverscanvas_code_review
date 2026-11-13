<?php
/**
 * WeaversCanvas - Email Sign-up Endpoint
 *
 * Receives email sign-ups from the landing page and sends them
 * via SMTP through GreenGeeks.
 *
 * Upload this file to your GreenGeeks hosting at:
 *   https://weaverscanvas.ca/send-email.php
 *
 * 1. Upload this file
 * 2. Create send-email-config.php (copy from .env.example.php)
 * 3. Set the SMTP_PASSWORD in the config file
 *
 * Abuse protection:
 *  - Per-IP rate limiting: at most MAX_SIGNUPS_PER_HOUR requests per IP.
 *  - A honeypot field ("company") is discarded silently if it is filled in.
 *  - Cross-origin browser requests are rejected (CORS is not wildcarded).
 */

header('Content-Type: application/json; charset=utf-8');

// Allow the site itself, and same-origin requests. Sending '*' would let any
// site on the internet post to this endpoint.
$allowedOrigin = 'https://weaverscanvas.ca';
$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
header('Vary: Origin');
if ($origin !== '' && $origin === $allowedOrigin) {
    header('Access-Control-Allow-Origin: ' . $allowedOrigin);
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Handle CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// Read JSON input
$input = json_decode(file_get_contents('php://input'), true);
if (!$input || empty($input['email'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Email is required']);
    exit;
}

// --- Rate limiting --------------------------------------------------------
// This runs before the honeypot check, so a bot cannot bypass the limit by
// filling in the honeypot field.
define('MAX_SIGNUPS_PER_HOUR', 10);
define('RATE_LIMIT_WINDOW', 3600);

function _client_ip() {
    // Cloudflare / GreenGeeks may put the real address in these headers.
    foreach (array('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP') as $hdr) {
        if (!empty($_SERVER[$hdr])) {
            $parts = explode(',', $_SERVER[$hdr]);
            $ip = trim($parts[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
}

function _rate_limit_dir() {
    $dir = sys_get_temp_dir() . '/wc-signup-rl';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir;
}

function _rate_limit_ok($ip) {
    $file = _rate_limit_dir() . '/' . sha1($ip) . '.json';
    $now = time();
    $hits = array();
    if (is_readable($file)) {
        $raw = json_decode((string)@file_get_contents($file), true);
        if (is_array($raw)) {
            foreach ($raw as $t) {
                if (is_numeric($t) && ($now - (int)$t) < RATE_LIMIT_WINDOW) $hits[] = (int)$t;
            }
        }
    }
    if (count($hits) >= MAX_SIGNUPS_PER_HOUR) {
        // Rewrite the file so the window slides properly.
        @file_put_contents($file, json_encode($hits), LOCK_EX);
        return false;
    }
    $hits[] = $now;
    if (@file_put_contents($file, json_encode($hits), LOCK_EX) === false) {
        // The limiter could not record this hit, so it is not actually
        // limiting anything. Say so in the error log rather than pretending.
        error_log('WeaversCanvas: sign-up rate limiter could not write to ' . $file);
    }
    return true;
}

if (!_rate_limit_ok(_client_ip())) {
    http_response_code(429);
    header('Retry-After: ' . RATE_LIMIT_WINDOW);
    echo json_encode(['success' => false, 'error' => 'Too many requests. Please try again later.']);
    exit;
}

// --- Honeypot -------------------------------------------------------------
// A real person never sees this field, so it is always empty for them.
// Bots that fill in every field get a success response and nothing is sent.
if (!empty($input['company'])) {
    http_response_code(200);
    echo json_encode(['success' => true, 'message' => 'Received']);
    exit;
}

$email = filter_var(trim($input['email']), FILTER_VALIDATE_EMAIL);
if (!$email) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid email address']);
    exit;
}

$timestamp = $input['timestamp'] ?? date('c');

// --- Load SMTP credentials ---
// Create send-email-config.php with your SMTP password
// (copy from .env.example.php and fill in the password)
$config = [];
$configFile = __DIR__ . '/send-email-config.php';
if (file_exists($configFile)) {
    $config = require $configFile;
}

$smtpPassword = $config['smtp_password'] ?? getenv('SMTP_PASSWORD') ?? '';

// --- Send email via PHPMailer ---

// Try to use PHPMailer from Composer (if installed via composer)
$autoloadPaths = [
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/PHPMailer/PHPMailer.php',
];

$phpmailerLoaded = false;
foreach ($autoloadPaths as $path) {
    if (file_exists($path)) {
        if (strpos($path, 'autoload.php') !== false) {
            require_once $path;
        } else {
            require_once $path;
            require_once dirname($path) . '/SMTP.php';
            require_once dirname($path) . '/Exception.php';
        }
        $phpmailerLoaded = true;
        break;
    }
}

if (!$phpmailerLoaded) {
    // Fallback: use PHP's built-in mail()
    $subject = 'New WeaversCanvas Sign-up';
    $message = "Email: $email\nSigned up: $timestamp\n";
    $headers = 'From: signups@weaverscanvas.ca' . "\r\n" .
               'Reply-To: ' . $email . "\r\n" .
               'X-Mailer: PHP/' . phpversion();

    $sent = mail('ebk@weaverscanvas.ca', $subject, $message, $headers);

    echo json_encode([
        'success' => $sent,
        'method' => 'mail',
        'message' => $sent ? 'Email sent' : 'Failed to send email'
    ]);
    exit;
}

// Use PHPMailer
$mail = new PHPMailer\PHPMailer\PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = 'mail.weaverscanvas.ca';
    $mail->SMTPAuth   = true;
    $mail->Username   = 'ebk@weaverscanvas.ca';
    $mail->Password   = $smtpPassword;
    $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = 587;

    $mail->setFrom('signups@weaverscanvas.ca', 'WeaversCanvas Sign-ups');
    $mail->addAddress('ebk@weaverscanvas.ca');
    $mail->addReplyTo($email);

    $mail->isHTML(false);
    $mail->Subject = 'New WeaversCanvas Sign-up';
    $mail->Body    = "Email: $email\nSigned up: $timestamp\n";

    $mail->send();

    echo json_encode([
        'success' => true,
        'method' => 'smtp',
        'message' => 'Email sent successfully'
    ]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'method' => 'smtp',
        'error' => 'Mail could not be sent: ' . $mail->ErrorInfo
    ]);
}
