<?php
session_start();

/* ======================================================
   🔒 MULTI-LAYER SECURITY HARDENING (100-Layer Style)
   ====================================================== */

// Prevent Clickjacking
header("X-Frame-Options: DENY");
// Prevent MIME sniffing
header("X-Content-Type-Options: nosniff");
// Basic XSS protection
header("X-XSS-Protection: 1; mode=block");
// Referrer Policy
header("Referrer-Policy: strict-origin-when-cross-origin");
// Strict Transport Security
header("Strict-Transport-Security: max-age=63072000; includeSubDomains; preload");
// Content Security Policy
header("Content-Security-Policy: default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';");
// Permissions Policy (new Feature Policy)
header("Permissions-Policy: clipboard-read=(self), clipboard-write=(self)");
// Disable caching sensitive pages
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");

// Regenerate Session ID frequently
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

// Set secure session cookie params
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

// CSRF Token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(64));
}

// ===== Logout Handling =====
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: #");
    exit;
}

// ===== Password Protection You Can Replace Password =====
$PASSWORD = "123445";
$SESSION_TIMEOUT = 900; // 15 minutes

if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    if (time() - $_SESSION['login_time'] > $SESSION_TIMEOUT) {
        session_unset();
        session_destroy();
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

if (isset($_POST['login_password'])) {
    if (hash_equals($PASSWORD, $_POST['login_password'])) {
        $_SESSION['logged_in'] = true;
        $_SESSION['login_time'] = time();
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = "Invalid password!";
    }
}

// ===== Converter Logic =====
$final_url = "";
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['ftp_url'])) {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        die("Access denied");
    }

    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        die("Invalid CSRF token");
    }

    $input_url = trim($_POST["ftp_url"]);
    if (!preg_match("#^ftp://#", $input_url)) {
        die("Invalid input format");
    }

   // Sanitize & Replace
   $clean_url = preg_replace("#^ftp://.*?@000\.000\.000\.000/public_html#", "", $input_url);
   $final_url = "https://yourdomain.xyz" . $clean_url;

    // Log securely
    $logFile = __DIR__ . "/links_log.txt";
    $logEntry = "[" . date("Y-m-d H:i:s") . "]\nFTP: " . htmlspecialchars($input_url) . "\nHTTPS: " . htmlspecialchars($final_url) . "\n----------------------\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

    $_SESSION['final_url'] = $final_url;
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if (!empty($_SESSION['final_url'])) {
    $final_url = $_SESSION['final_url'];
    unset($_SESSION['final_url']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Protected FTP → HTTPS Converter</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" type="image/png" href="icon/icon.png">
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">

<?php if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true): ?>
  <!-- ===== Login Form ===== -->
  <div class="bg-white shadow-xl rounded-2xl p-6 w-full max-w-sm" data-aos="fade-up">
    <h1 class="text-xl font-bold text-center mb-4">🔒 Protected Page</h1>
    <?php if (!empty($login_error)): ?>
      <p class="text-red-600 text-center mb-3"><?php echo htmlspecialchars($login_error); ?></p>
    <?php endif; ?>
    <form method="post" class="space-y-4">
      <input type="password" name="login_password" placeholder="Enter password"
             class="w-full px-4 py-3 border rounded-lg focus:outline-none focus:ring focus:border-blue-400 text-center" required>
      <button type="submit" 
              class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded-lg">
        Verify
      </button>
    </form>
  </div>

<?php else: ?>
  <!-- ===== Converter Page ===== -->
  <div class="bg-white shadow-2xl rounded-2xl p-6 w-full max-w-xl" data-aos="zoom-in">
    <h1 class="text-2xl font-bold text-center mb-4">FTP → HTTPS Converter</h1>
    <form method="post" class="space-y-4">
      <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
      <label class="block text-gray-700 font-medium mb-2">Enter FTP URL:</label>
      <div class="flex space-x-2">
        <input type="text" name="ftp_url" id="ftpInput" required
               placeholder="Paste your FTP link here..."
               class="flex-1 px-4 py-3 border rounded-lg focus:outline-none focus:ring focus:border-blue-400 text-sm">
        <button type="button" onclick="pasteFromClipboard()" 
                class="bg-yellow-500 hover:bg-yellow-600 text-white px-4 py-3 rounded-lg">
          Paste
        </button>
      </div>
      <button type="submit"
              class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded-lg mt-4">
        Generate Link
      </button>
    </form>

    <?php if ($final_url): ?>
      <div class="mt-6" data-aos="fade-up">
        <label class="block text-gray-700 font-medium mb-2">Final HTTPS Link:</label>
        <div class="flex flex-col sm:flex-row items-stretch sm:items-center space-y-2 sm:space-y-0 sm:space-x-2">
          
          <input type="text" id="finalLink" readonly
                 class="flex-1 px-4 py-3 border rounded-lg bg-gray-50 text-sm"
                 value="<?php echo htmlspecialchars($final_url); ?>">
            <button onclick="downloadLink()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-3 rounded-lg">
            Download
          </button>
          <button onclick="copyLink()" class="bg-green-600 hover:bg-green-700 text-white px-4 py-3 rounded-lg">
            Copy
          </button>
        </div>
      </div>
    <?php endif; ?>

    <div class="mt-6 text-center">
      <a href="?logout=1" class="text-red-600 underline">Logout</a>
    </div>
  </div>
<?php endif; ?>

<!-- ===== Sticky Footer ===== -->
<footer class="fixed bottom-0 left-0 w-full bg-gray-800 text-white text-center py-2 text-sm shadow-inner">
  Developed BY <span class="font-semibold">Md Abdur Razzak</span>
</footer>

<script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
<script>AOS.init();</script>
<script>
function copyLink() {
  const linkField = document.getElementById("finalLink");
  linkField.select();
  linkField.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(linkField.value).then(() => {
    Swal.fire({
      toast: true,
      position: 'top-end',
      icon: 'success',
      title: '✅ Link copied!',
      showConfirmButton: false,
      timer: 2000
    });
  });
}

function pasteFromClipboard() {
  navigator.clipboard.readText().then(text => {
    document.getElementById("ftpInput").value = text;
  });
}

function downloadLink() {
  const linkField = document.getElementById("finalLink");
  if (linkField && linkField.value) {
    window.open(linkField.value, "_blank");
  }
}
</script>
</body>
</html>
