<?php
declare(strict_types=1);
session_start();

/*
DIma Shop - Single-file PHP/MySQL Installer (Apache / DirectAdmin)
- بدون Node/TypeScript. فقط PHP و MySQL
- Tailwind از CDN (بدون npm)
- ایجاد ساختار پروژه، فایل‌های PHP، .htaccess، اجرای اسکیما، تنظیم Config، ساخت/بروزرسانی ادمین
- پس از نصب، این فایل را حذف کنید.
*/

if (empty($_SESSION['_installer_csrf'])) {
  $_SESSION['_installer_csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['_installer_csrf'];

function h($v){ return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
function ensure_dir(string $path){ if(!is_dir($path)) @mkdir($path, 0755, true); }
function write_file(string $path, string $content) {
  ensure_dir(dirname($path));
  if (file_put_contents($path, $content) === false) throw new RuntimeException("نوشتن فایل ناموفق: $path");
}
function replace_const(string $content, string $name, string $value, bool $quote): string {
  $pattern = '/(public\\s+const\\s+' . preg_quote($name, '/') . '\\s*=\\s*)([^;]+)(;)/';
  if ($quote) $replacement = '$1\'' . addslashes($value) . '\'$3';
  else $replacement = '$1' . $value . '$3';
  return preg_replace($pattern, $replacement, $content, 1) ?? $content;
}

$defaults = [
  'db_host' => '127.0.0.1',
  'db_name' => 'dimashop',
  'db_user' => 'root',
  'db_pass' => '',
  'app_url' => (function(){
    $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return $proto . '://' . $host;
  })(),
  'contact_email' => 'info@dima.shop.ir',
  'merchant_id' => '',
  'sandbox' => '1',
  'admin_email' => 'admin@example.com',
  'admin_password' => '',
];

$errors = [];
$log = [];
$done = false;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
  if (!hash_equals($csrf, (string)($_POST['_csrf'] ?? ''))) {
    $errors[] = 'CSRF token نامعتبر است. صفحه را رفرش کنید.';
  } else {
    $data = [
      'db_host' => trim((string)($_POST['db_host'] ?? $defaults['db_host'])),
      'db_name' => trim((string)($_POST['db_name'] ?? $defaults['db_name'])),
      'db_user' => trim((string)($_POST['db_user'] ?? $defaults['db_user'])),
      'db_pass' => (string)($_POST['db_pass'] ?? $defaults['db_pass']),
      'app_url' => rtrim(trim((string)($_POST['app_url'] ?? $defaults['app_url'])), '/'),
      'contact_email' => trim((string)($_POST['contact_email'] ?? $defaults['contact_email'])),
      'merchant_id' => trim((string)($_POST['merchant_id'] ?? '')),
      'sandbox' => ((string)($_POST['sandbox'] ?? '1')) === '1' ? '1' : '0',
      'admin_email' => trim((string)($_POST['admin_email'] ?? 'admin@example.com')),
      'admin_password' => (string)($_POST['admin_password'] ?? ''),
    ];

    // 1) ایجاد ساختار و فایل‌های پروژه
    try {
      build_project_files();
      $log[] = 'فایل‌ها و پوشه‌های پروژه ایجاد شد.';
    } catch (Throwable $e) {
      $errors[] = 'ایجاد فایل‌ها ناموفق: ' . $e->getMessage();
    }

    // 2) بروزرسانی Config با ورودی‌ها
    if (!$errors) {
      try {
        $cfgFile = __DIR__ . '/app/Config.php';
        $cfg = file_get_contents($cfgFile);
        if ($cfg === false) throw new RuntimeException('خواندن Config ناموفق.');

        @copy($cfgFile, $cfgFile . '.bak');

        $cfg = replace_const($cfg, 'DB_HOST', $data['db_host'], true);
        $cfg = replace_const($cfg, 'DB_NAME', $data['db_name'], true);
        $cfg = replace_const($cfg, 'DB_USER', $data['db_user'], true);
        $cfg = replace_const($cfg, 'DB_PASS', $data['db_pass'], true);
        $cfg = replace_const($cfg, 'APP_URL', $data['app_url'], true);
        $cfg = replace_const($cfg, 'CONTACT_EMAIL', $data['contact_email'], true);
        $cfg = replace_const($cfg, 'ZARINPAL_MERCHANT_ID', $data['merchant_id'], true);
        $cfg = replace_const($cfg, 'ZARINPAL_SANDBOX', $data['sandbox'] === '1' ? 'true' : 'false', false);
        $cfg = replace_const($cfg, 'APP_DEBUG', 'false', false);

        write_file($cfgFile, $cfg);
        $log[] = 'تنظیمات app/Config.php ذخیره شد.';
      } catch (Throwable $e) {
        $errors[] = 'بروزرسانی Config ناموفق: ' . $e->getMessage();
      }
    }

    // 3) اتصال به دیتابیس و اجرای اسکیما
    if (!$errors) {
      try {
        $dsn = 'mysql:host=' . $data['db_host'] . ';dbname=' . $data['db_name'] . ';charset=utf8mb4';
        $pdo = new PDO($dsn, $data['db_user'], $data['db_pass'], [
          PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
          PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $log[] = 'اتصال به دیتابیس موفق بود.';

        $schemaFile = __DIR__ . '/database/schema.sql';
        $sql = file_get_contents($schemaFile) ?: '';
        $stmts = preg_split('/;\\s*\\n/', $sql);
        foreach ($stmts as $stmt) {
          $stmt = trim($stmt);
          if ($stmt !== '') $pdo->exec($stmt);
        }
        $log[] = 'اسکیما اجرا شد.';
      } catch (Throwable $e) {
        $errors[] = 'اجرای دیتابیس ناموفق: ' . $e->getMessage();
      }
    }

    // 4) ساخت/بروزرسانی ادمین
    if (!$errors && $data['admin_email'] !== '' && $data['admin_password'] !== '') {
      try {
        $hash = password_hash($data['admin_password'], PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("SELECT id FROM users WHERE role='admin' LIMIT 1");
        $stmt->execute();
        $row = $stmt->fetch();
        if ($row) {
          $upd = $pdo->prepare("UPDATE users SET email=:e, password_hash=:h WHERE id=:id");
          $upd->execute([':e'=>$data['admin_email'],':h'=>$hash,':id'=>(int)$row['id']]);
          $log[] = 'مدیر به‌روزرسانی شد.';
        } else {
          $ins = $pdo->prepare("INSERT INTO users (email, password_hash, role) VALUES (:e,:h,'admin')");
          $ins->execute([':e'=>$data['admin_email'],':h'=>$hash]);
          $log[] = 'مدیر ایجاد شد.';
        }
      } catch (Throwable $e) {
        $errors[] = 'ثبت مدیر ناموفق: ' . $e->getMessage();
      }
    } else {
      $log[] = 'هشدار: رمز عبور مدیر وارد نشد؛ مدیر پیش‌فرض باقی می‌ماند.';
    }

    // 5) قفل نصب
    if (!$errors) {
      @file_put_contents(__DIR__ . '/installed.lock', date('c'));
      $done = true;
    }
  }
}

/* ---------- تولید فایل‌های پروژه (فقط PHP/MySQL) ---------- */
function build_project_files(): void {
  // روت
  write_file(__DIR__ . '/bootstrap.php', bootstrapPhp());
  write_file(__DIR__ . '/.htaccess', rootHtaccess());
  write_file(__DIR__ . '/README.md', readmeMd());

  // دیتابیس
  ensure_dir(__DIR__ . '/database');
  write_file(__DIR__ . '/database/schema.sql', schemaSql());

  // app core
  write_file(__DIR__ . '/app/Config.php', configPhp());
  write_file(__DIR__ . '/app/Database.php', databasePhp());
  write_file(__DIR__ . '/app/Router.php', routerPhp());
  write_file(__DIR__ . '/app/Controller.php', controllerPhp());
  write_file(__DIR__ . '/app/Model.php', modelPhp());
  write_file(__DIR__ . '/app/Helpers.php', helpersPhp());

  // middleware
  write_file(__DIR__ . '/app/Middleware/Csrf.php', csrfPhp());
  write_file(__DIR__ . '/app/Middleware/RateLimit.php', rateLimitPhp());

  // services
  write_file(__DIR__ . '/app/Services/Cart.php', cartPhp());
  write_file(__DIR__ . '/app/Services/Payment/Zarinpal.php', zarinpalPhp());

  // models
  write_file(__DIR__ . '/app/Models/Product.php', modelProductPhp());
  write_file(__DIR__ . '/app/Models/Order.php', modelOrderPhp());
  write_file(__DIR__ . '/app/Models/Coupon.php', modelCouponPhp());

  // controllers (front)
  write_file(__DIR__ . '/app/Controllers/HomeController.php', homeControllerPhp());
  write_file(__DIR__ . '/app/Controllers/ProductController.php', productControllerPhp());
  write_file(__DIR__ . '/app/Controllers/CartController.php', cartControllerPhp());
  write_file(__DIR__ . '/app/Controllers/CheckoutController.php', checkoutControllerPhp());
  write_file(__DIR__ . '/app/Controllers/PaymentController.php', paymentControllerPhp());

  // controllers (admin)
  write_file(__DIR__ . '/app/Controllers/Admin/AuthController.php', adminAuthControllerPhp());
  write_file(__DIR__ . '/app/Controllers/Admin/DashboardController.php', adminDashboardControllerPhp());
  write_file(__DIR__ . '/app/Controllers/Admin/ProductsController.php', adminProductsControllerPhp());
  write_file(__DIR__ . '/app/Controllers/Admin/OrdersController.php', adminOrdersControllerPhp());

  // views (front)
  write_file(__DIR__ . '/app/Views/layout.php', viewLayoutPhp());
  write_file(__DIR__ . '/app/Views/home.php', viewHomePhp());
  write_file(__DIR__ . '/app/Views/product-detail.php', viewProductDetailPhp());
  write_file(__DIR__ . '/app/Views/cart.php', viewCartPhp());
  write_file(__DIR__ . '/app/Views/checkout.php', viewCheckoutPhp());
  write_file(__DIR__ . '/app/Views/order-success.php', viewOrderSuccessPhp());

  // views (admin)
  write_file(__DIR__ . '/app/Views/admin/layout.php', viewAdminLayoutPhp());
  write_file(__DIR__ . '/app/Views/admin/login.php', viewAdminLoginPhp());
  write_file(__DIR__ . '/app/Views/admin/dashboard.php', viewAdminDashboardPhp());
  write_file(__DIR__ . '/app/Views/admin/products.php', viewAdminProductsPhp());
  write_file(__DIR__ . '/app/Views/admin/orders.php', viewAdminOrdersPhp());

  // public
  write_file(__DIR__ . '/public/index.php', publicIndexPhp());
  write_file(__DIR__ . '/public/.htaccess', publicHtaccess());
  ensure_dir(__DIR__ . '/public/uploads');
  write_file(__DIR__ . '/public/uploads/.htaccess', publicUploadsHtaccess());
  write_file(__DIR__ . '/public/placeholder.svg', placeholderSvg());
}

/* ---------- محتواهای فایل‌ها (نسخه فقط PHP با Tailwind از CDN) ---------- */

function readmeMd(): string {
return "# DIma Shop (PHP + MySQL)\n\n- نصب: dimashop-installer.php را اجرا کنید.\n- DocumentRoot روی public باشد یا از .htaccess روت استفاده کنید.\n- Callback زرین‌پال: /payment/callback\n";
}

function rootHtaccess(): string {
return "RewriteEngine On\n\n# Route everything to /public when DocumentRoot is not set to public\nRewriteCond %{REQUEST_URI} !^/public/\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^(.*)$ public/$1 [L,QSA]\n\nDirectoryIndex public/index.php\n";
}

function publicHtaccess(): string {
return "<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^ index.php [QSA,L]\n</IfModule>\n\nOptions -Indexes\nDirectoryIndex index.php index.html\n\n<IfModule mod_headers.c>\nHeader set X-Content-Type-Options \"nosniff\"\nHeader set X-Frame-Options \"SAMEORIGIN\"\nHeader set Referrer-Policy \"strict-origin-when-cross-origin\"\nHeader set X-XSS-Protection \"1; mode=block\"\nHeader set Content-Security-Policy \"default-src 'self'; img-src 'self' data: https:; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'\"\n</IfModule>\n";
}

function publicUploadsHtaccess(): string {
return "php_flag engine off\nRemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8\nRemoveType .php .phtml .php3 .php4 .php5 .php7 .php8\n<FilesMatch \"\\.(php|phtml|php\\d+)$\">Require all denied</FilesMatch>\nOptions -ExecCGI\n";
}

function placeholderSvg(): string {
return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"800\" height=\"600\"><rect width=\"100%\" height=\"100%\" fill=\"#f1f5f9\"/><text x=\"50%\" y=\"50%\" dominant-baseline=\"middle\" text-anchor=\"middle\" fill=\"#94a3b8\" font-family=\"sans-serif\" font-size=\"24\">Placeholder</text></svg>";
}

function publicIndexPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/../bootstrap.php';

use App\Router;
use App\Controllers\HomeController;
use App\Controllers\ProductController;
use App\Controllers\CartController;
use App\Controllers\CheckoutController;
use App\Controllers\PaymentController;
use App\Controllers\Admin\AuthController as AdminAuthController;
use App\Controllers\Admin\DashboardController as AdminDashboardController;
use App\Controllers\Admin\ProductsController as AdminProductsController;
use App\Controllers\Admin\OrdersController as AdminOrdersController;

$router = new Router();

// Front routes
$router->get('/', [HomeController::class, 'index']);
$router->get('/product/{slug}', [ProductController::class, 'show']);

$router->get('/cart', [CartController::class, 'index']);
$router->post('/cart/add', [CartController::class, 'add']);
$router->post('/cart/update', [CartController::class, 'update']);
$router->post('/cart/remove', [CartController::class, 'remove']);
$router->post('/cart/clear', [CartController::class, 'clear']);

$router->get('/checkout', [CheckoutController::class, 'index']);
$router->post('/checkout', [CheckoutController::class, 'placeOrder']);

// Payment
$router->get('/payment/callback', [PaymentController::class, 'callback']);

// Order success
$router->get('/order/success/{id}', [CheckoutController::class, 'success']);

// Admin
$router->get('/admin', [AdminDashboardController::class, 'index']);
$router->get('/admin/login', [AdminAuthController::class, 'loginForm']);
$router->post('/admin/login', [AdminAuthController::class, 'login']);
$router->get('/admin/logout', [AdminAuthController::class, 'logout']);

$router->get('/admin/dashboard', [AdminDashboardController::class, 'index']);
$router->get('/admin/products', [AdminProductsController::class, 'index']);
$router->post('/admin/products/create', [AdminProductsController::class, 'create']);
$router->post('/admin/products/delete', [AdminProductsController::class, 'delete']);

$router->get('/admin/orders', [AdminOrdersController::class, 'index']);
$router->post('/admin/orders/status', [AdminOrdersController::class, 'updateStatus']);

$router->dispatch();
PHP;
}

function bootstrapPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

spl_autoload_register(function ($class) {
  $prefix = 'App\\';
  $base_dir = __DIR__ . '/app/';
  $len = strlen($prefix);
  if (strncmp($prefix, $class, $len) !== 0) return;
  $relative_class = substr($class, $len);
  $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
  if (file_exists($file)) require $file;
});

require_once __DIR__ . '/app/Config.php';
require_once __DIR__ . '/app/Helpers.php';

App\Hooks::init();
PHP;
}

function configPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App;

class Config
{
  // Database
  public const DB_HOST = '127.0.0.1';
  public const DB_NAME = 'dimashop';
  public const DB_USER = 'root';
  public const DB_PASS = '';
  public const DB_CHARSET = 'utf8mb4';

  // App
  public const APP_URL = 'https://example.com';
  public const APP_NAME = 'DIma Shop';
  public const APP_LOCALE = 'fa_IR';
  public const APP_TIMEZONE = 'Asia/Tehran';
  public const APP_DEBUG = true;
  public const CONTACT_EMAIL = 'info@dima.shop.ir';

  // CSRF
  public const CSRF_TOKEN_KEY = '_csrf';

  // Currency
  public const CURRENCY = 'Toman';
  public const ZARINPAL_AMOUNT_IN_RIAL = true;

  // ZarinPal
  public const ZARINPAL_MERCHANT_ID = '';
  public const ZARINPAL_SANDBOX = true;

  public static function zarinpalEndpoints(): array
  {
      $sandbox = self::ZARINPAL_SANDBOX;
      return [
          'request' => $sandbox
              ? 'https://sandbox.zarinpal.com/pg/v4/payment/request.json'
              : 'https://api.zarinpal.com/pg/v4/payment/request.json',
          'verify' => $sandbox
              ? 'https://sandbox.zarinpal.com/pg/v4/payment/verify.json'
              : 'https://api.zarinpal.com/pg/v4/payment/verify.json',
          'startpay' => $sandbox
              ? 'https://sandbox.zarinpal.com/pg/StartPay/'
              : 'https://www.zarinpal.com/pg/StartPay/',
      ];
  }
}
PHP;
}

function databasePhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App;

use PDO;
use PDOException;

class Database
{
  private static ?PDO $pdo = null;

  public static function pdo(): PDO
  {
      if (self::$pdo === null) {
          $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', Config::DB_HOST, Config::DB_NAME, Config::DB_CHARSET);
          $options = [
              PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
              PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
              PDO::ATTR_EMULATE_PREPARES => false,
          ];
          try {
              self::$pdo = new PDO($dsn, Config::DB_USER, Config::DB_PASS, $options);
          } catch (PDOException $e) {
              if (Config::APP_DEBUG) {
                  die('DB Connection failed: ' . $e->getMessage());
              }
              die('DB Connection failed.');
          }
      }
      return self::$pdo;
  }
}
PHP;
}

function routerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App;

class Router
{
  private array $routes = ['GET' => [], 'POST' => []];

  public function get(string $pattern, $handler): void
  {
      $this->routes['GET'][$pattern] = $handler;
  }
  public function post(string $pattern, $handler): void
  {
      $this->routes['POST'][$pattern] = $handler;
  }

  public function dispatch(): void
  {
      $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
      $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
      $uri = rtrim($uri, '/') ?: '/';

      foreach ($this->routes[$method] as $pattern => $handler) {
          $regex = preg_replace('#\\{([a-zA-Z_][a-zA-Z0-9_]*)\\}#', '(?P<$1>[^/]+)', $pattern);
          $regex = '#^' . rtrim($regex, '/') . '$#';
          if (preg_match($regex, $uri, $matches)) {
              $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
              return $this->invoke($handler, $params);
          }
      }

      http_response_code(404);
      echo '404 Not Found';
  }

  private function invoke($handler, array $params): void
  {
      if (is_callable($handler)) {
          echo call_user_func_array($handler, $params);
          return;
      }
      if (is_array($handler) && count($handler) === 2) {
          [$class, $method] = $handler;
          $controller = new $class();
          echo call_user_func_array([$controller, $method], $params);
          return;
      }
      throw new \RuntimeException('Invalid route handler');
  }
}
PHP;
}

function controllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App;

class Controller
{
  protected function view(string $template, array $data = []): string
  {
      extract($data);
      ob_start();
      include __DIR__ . "/Views/{$template}.php";
      return ob_get_clean();
  }

  protected function redirect(string $path): void
  {
      header('Location: ' . rtrim(Config::APP_URL, '/') . $path);
      exit;
  }

  protected function isPost(): bool
  {
      return ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
  }

  protected function requireAdmin(): void
  {
      if (!isset($_SESSION['admin_id'])) {
          $this->redirect('/admin/login');
      }
  }
}
PHP;
}

function modelPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App;

use PDO;

abstract class Model
{
  protected PDO $db;
  public function __construct()
  {
      $this->db = Database::pdo();
  }
}
PHP;
}

function helpersPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App;

class Helpers
{
  public static function e(string $str): string
  {
      return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
  }
  public static function money(int|float $amount): string
  {
      $formatted = number_format($amount);
      return $formatted . ' ' . Config::CURRENCY;
  }
  public static function csrfToken(): string
  {
      if (!isset($_SESSION[Config::CSRF_TOKEN_KEY])) {
          $_SESSION[Config::CSRF_TOKEN_KEY] = bin2hex(random_bytes(32));
      }
      return $_SESSION[Config::CSRF_TOKEN_KEY];
  }
  public static function verifyCsrf(?string $token): bool
  {
      return isset($_SESSION[Config::CSRF_TOKEN_KEY]) && hash_equals($_SESSION[Config::CSRF_TOKEN_KEY], (string)$token);
  }

  public static function rialize(int $amountToman): int
  {
      return Config::ZARINPAL_AMOUNT_IN_RIAL ? $amountToman * 10 : $amountToman;
  }
}

class Hooks
{
  private static array $actions = [];
  private static array $filters = [];

  public static function init(): void {}

  public static function addAction(string $hook, callable $cb, int $prio = 10): void
  {
      self::$actions[$hook][$prio][] = $cb;
  }
  public static function doAction(string $hook, ...$args): void
  {
      if (!isset(self::$actions[$hook])) return;
      ksort(self::$actions[$hook]);
      foreach (self::$actions[$hook] as $cbs) {
          foreach ($cbs as $cb) $cb(...$args);
      }
  }

  public static function addFilter(string $hook, callable $cb, int $prio = 10): void
  {
      self::$filters[$hook][$prio][] = $cb;
  }
  public static function applyFilters(string $hook, $value, ...$args)
  {
      if (!isset(self::$filters[$hook])) return $value;
      ksort(self::$filters[$hook]);
      foreach (self::$filters[$hook] as $cbs) {
          foreach ($cbs as $cb) $value = $cb($value, ...$args);
      }
      return $value;
  }
}
PHP;
}

function csrfPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Middleware;

use App\Config;

class Csrf
{
  public static function requireToken(): void
  {
      $token = $_POST[Config::CSRF_TOKEN_KEY] ?? null;
      if (!\App\Helpers::verifyCsrf($token)) {
          http_response_code(400);
          exit('Invalid CSRF token');
      }
  }
}
PHP;
}

function rateLimitPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Middleware;

class RateLimit {
public static function allow(string $key, int $maxPerMinute = 30): bool {
  $dir = sys_get_temp_dir() . '/dima_rate';
  if (!is_dir($dir)) @mkdir($dir, 0700, true);
  $file = $dir . '/' . sha1($key . '|' . date('YmdHi')) . '.cnt';
  $count = 0;
  if (file_exists($file)) {
    $count = (int)file_get_contents($file);
  }
  $count++;
  file_put_contents($file, (string)$count, LOCK_EX);
  return $count <= $maxPerMinute;
}
}
PHP;
}

function cartPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Services;

use App\Models\Product;

class Cart
{
  private const KEY = '_cart';

  public static function items(): array
  {
      return $_SESSION[self::KEY]['items'] ?? [];
  }

  public static function add(int $productId, int $qty = 1, ?int $variationId = null): void
  {
      $key = $productId . ':' . ($variationId ?? 0);
      $items = self::items();
      if (isset($items[$key])) {
          $items[$key]['qty'] += $qty;
      } else {
          $items[$key] = ['product_id' => $productId, 'variation_id' => $variationId, 'qty' => $qty];
      }
      $_SESSION[self::KEY]['items'] = $items;
  }

  public static function update(string $key, int $qty): void
  {
      $items = self::items();
      if (isset($items[$key])) {
          $items[$key]['qty'] = max(1, $qty);
          $_SESSION[self::KEY]['items'] = $items;
      }
  }

  public static function remove(string $key): void
  {
      $items = self::items();
      unset($items[$key]);
      $_SESSION[self::KEY]['items'] = $items;
  }

  public static function clear(): void
  {
      $_SESSION[self::KEY] = ['items' => []];
  }

  public static function totals(): array
  {
      $subtotal = 0;
      $lines = [];
      foreach (self::items() as $key => $line) {
          $product = (new Product())->findById($line['product_id']);
          if (!$product) continue;
          $price = (int)($product['sale_price'] ?? $product['price']);
          $lineTotal = $price * $line['qty'];
          $subtotal += $lineTotal;
          $lines[] = [
              'key' => $key,
              'product' => $product,
              'qty' => $line['qty'],
              'price' => $price,
              'total' => $lineTotal,
          ];
      }
      $discount = 0;
      if (!empty($_SESSION['_coupon'])) {
          $coupon = $_SESSION['_coupon'];
          if ($coupon['type'] === 'percent') {
              $discount = (int)floor($subtotal * ($coupon['amount'] / 100));
          } else {
              $discount = (int)$coupon['amount'];
          }
          $discount = min($discount, $subtotal);
      }
      $tax = (int)floor(($subtotal - $discount) * 0.0);
      $shipping = (int)($_SESSION['_shipping_cost'] ?? 0);

      $total = max(0, $subtotal - $discount + $tax + $shipping);

      return compact('lines', 'subtotal', 'discount', 'tax', 'shipping', 'total');
  }
}
PHP;
}

function zarinpalPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Services\Payment;

use App\Config;

class Zarinpal
{
  public static function requestPayment(int $amountToman, string $callbackUrl, string $description, ?string $email = null, ?string $mobile = null): array
  {
      $endpoints = Config::zarinpalEndpoints();
      $payload = [
          'merchant_id' => Config::ZARINPAL_MERCHANT_ID,
          'amount' => \App\Helpers::rialize($amountToman),
          'callback_url' => $callbackUrl,
          'description' => $description,
          'metadata' => [
              'email' => $email,
              'mobile' => $mobile,
          ],
      ];
      $resp = self::postJson($endpoints['request'], $payload);
      if (isset($resp['data']) && $resp['data']['code'] == 100) {
          $authority = $resp['data']['authority'];
          $startPay = $endpoints['startpay'] . $authority;
          return ['success' => true, 'authority' => $authority, 'start_pay' => $startPay];
      }
      $message = $resp['errors']['message'] ?? 'Payment request failed';
      return ['success' => false, 'message' => $message, 'response' => $resp];
  }

  public static function verifyPayment(int $amountToman, string $authority): array
  {
      $endpoints = Config::zarinpalEndpoints();
      $payload = [
          'merchant_id' => Config::ZARINPAL_MERCHANT_ID,
          'amount' => \App\Helpers::rialize($amountToman),
          'authority' => $authority,
      ];
      $resp = self::postJson($endpoints['verify'], $payload);
      if (isset($resp['data']) && $resp['data']['code'] == 100) {
          return ['success' => true, 'ref_id' => $resp['data']['ref_id']];
      }
      $message = $resp['errors']['message'] ?? 'Payment verify failed';
      return ['success' => false, 'message' => $message, 'response' => $resp];
  }

  private static function postJson(string $url, array $data): array
  {
      $ch = curl_init($url);
      curl_setopt_array($ch, [
          CURLOPT_POST => true,
          CURLOPT_RETURNTRANSFER => true,
          CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
          CURLOPT_POSTFIELDS => json_encode($data, JSON_UNESCAPED_UNICODE),
          CURLOPT_TIMEOUT => 30,
      ]);
      $result = curl_exec($ch);
      $err = curl_error($ch);
      curl_close($ch);
      if ($err) {
          return ['errors' => ['message' => 'cURL error: ' . $err]];
      }
      $decoded = json_decode($result, true);
      return is_array($decoded) ? $decoded : ['errors' => ['message' => 'Invalid JSON response']];
  }
}
PHP;
}

function modelProductPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Models;

use App\Model;
use PDO;

class Product extends Model
{
  public function latest(int $limit = 12): array
  {
      $stmt = $this->db->prepare("SELECT * FROM products WHERE status='publish' ORDER BY id DESC LIMIT :lim");
      $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
      $stmt->execute();
      return $stmt->fetchAll();
  }

  public function findBySlug(string $slug): ?array
  {
      $stmt = $this->db->prepare("SELECT * FROM products WHERE slug = :slug AND status='publish' LIMIT 1");
      $stmt->execute([':slug' => $slug]);
      $row = $stmt->fetch();
      return $row ?: null;
  }

  public function findById(int $id): ?array
  {
      $stmt = $this->db->prepare("SELECT * FROM products WHERE id = :id LIMIT 1");
      $stmt->execute([':id' => $id]);
      $row = $stmt->fetch();
      return $row ?: null;
  }

  public function create(array $data): int
  {
      $stmt = $this->db->prepare("INSERT INTO products (name, slug, description, price, sale_price, sku, stock_qty, status) VALUES (:name, :slug, :description, :price, :sale_price, :sku, :stock_qty, :status)");
      $stmt->execute([
          ':name' => $data['name'],
          ':slug' => $data['slug'],
          ':description' => $data['description'] ?? '',
          ':price' => (int)$data['price'],
          ':sale_price' => $data['sale_price'] !== '' ? (int)$data['sale_price'] : null,
          ':sku' => $data['sku'] ?? null,
          ':stock_qty' => (int)($data['stock_qty'] ?? 0),
          ':status' => $data['status'] ?? 'publish',
      ]);
      return (int)$this->db->lastInsertId();
  }

  public function delete(int $id): void
  {
      $stmt = $this->db->prepare("DELETE FROM products WHERE id=:id");
      $stmt->execute([':id' => $id]);
  }
}
PHP;
}

function modelOrderPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Models;

use App\Model;
use PDO;

class Order extends Model
{
  public function create(array $data, array $items): int
  {
      $this->db->beginTransaction();
      try {
          $stmt = $this->db->prepare("INSERT INTO orders (user_id, status, total, subtotal, discount, shipping_cost, tax, payment_status, payment_method, payment_ref, email, name, phone, address, city, postal_code) VALUES (:user_id, :status, :total, :subtotal, :discount, :shipping_cost, :tax, :payment_status, :payment_method, :payment_ref, :email, :name, :phone, :address, :city, :postal_code)");
          $stmt->execute([
              ':user_id' => $data['user_id'] ?? null,
              ':status' => $data['status'] ?? 'pending',
              ':total' => (int)$data['total'],
              ':subtotal' => (int)$data['subtotal'],
              ':discount' => (int)$data['discount'],
              ':shipping_cost' => (int)$data['shipping_cost'],
              ':tax' => (int)$data['tax'],
              ':payment_status' => $data['payment_status'] ?? 'unpaid',
              ':payment_method' => $data['payment_method'] ?? 'zarinpal',
              ':payment_ref' => $data['payment_ref'] ?? null,
              ':email' => $data['email'] ?? null,
              ':name' => $data['name'] ?? null,
              ':phone' => $data['phone'] ?? null,
              ':address' => $data['address'] ?? null,
              ':city' => $data['city'] ?? null,
              ':postal_code' => $data['postal_code'] ?? null,
          ]);
          $orderId = (int)$this->db->lastInsertId();

          $ins = $this->db->prepare("INSERT INTO order_items (order_id, product_id, variation_id, name, sku, price, qty, total) VALUES (:order_id, :product_id, :variation_id, :name, :sku, :price, :qty, :total)");
          foreach ($items as $it) {
              $ins->execute([
                  ':order_id' => $orderId,
                  ':product_id' => $it['product_id'],
                  ':variation_id' => $it['variation_id'] ?? null,
                  ':name' => $it['name'],
                  ':sku' => $it['sku'] ?? null,
                  ':price' => (int)$it['price'],
                  ':qty' => (int)$it['qty'],
                  ':total' => (int)$it['total'],
              ]);
          }

          $this->db->commit();
          return $orderId;
      } catch (\Throwable $e) {
          $this->db->rollBack();
          throw $e;
      }
  }

  public function markPaid(int $orderId, string $refId): void
  {
      $stmt = $this->db->prepare("UPDATE orders SET payment_status='paid', status='processing', payment_ref=:ref WHERE id=:id");
      $stmt->execute([':ref' => $refId, ':id' => $orderId]);
  }

  public function find(int $id): ?array
  {
      $stmt = $this->db->prepare("SELECT * FROM orders WHERE id=:id");
      $stmt->execute([':id' => $id]);
      $row = $stmt->fetch();
      return $row ?: null;
  }

  public function all(int $limit = 50): array
  {
      $stmt = $this->db->prepare("SELECT * FROM orders ORDER BY id DESC LIMIT :lim");
      $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
      $stmt->execute();
      return $stmt->fetchAll();
  }
}
PHP;
}

function modelCouponPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Models;

use App\Model;

class Coupon extends Model
{
  public function findActiveByCode(string $code): ?array
  {
      $stmt = $this->db->prepare("SELECT * FROM coupons WHERE code=:code AND (expires_at IS NULL OR expires_at > NOW()) AND (usage_limit IS NULL OR usage_limit > used) LIMIT 1");
      $stmt->execute([':code' => $code]);
      $row = $stmt->fetch();
      return $row ?: null;
  }

  public function incrementUse(int $id): void
  {
      $stmt = $this->db->prepare("UPDATE coupons SET used = used + 1 WHERE id=:id AND (usage_limit IS NULL OR used < usage_limit)");
      $stmt->execute([':id' => $id]);
  }
}
PHP;
}

function homeControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Controller;
use App\Models\Product;

class HomeController extends Controller
{
  public function index(): string
  {
      $products = (new Product())->latest(12);
      return $this->view('home', compact('products'));
  }
}
PHP;
}

function productControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Controller;
use App\Models\Product;

class ProductController extends Controller
{
  public function show(string $slug): string
  {
      $product = (new Product())->findBySlug($slug);
      if (!$product) {
          http_response_code(404);
          return 'محصول یافت نشد';
      }
      return $this->view('product-detail', compact('product'));
  }
}
PHP;
}

function cartControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Controller;
use App\Middleware\Csrf;
use App\Services\Cart;

class CartController extends Controller
{
  public function index(): string
  {
      $totals = Cart::totals();
      return $this->view('cart', compact('totals'));
  }

  public function add(): string
  {
      \App\Middleware\Csrf::requireToken();
      $productId = (int)($_POST['product_id'] ?? 0);
      $qty = (int)($_POST['qty'] ?? 1);
      if ($productId > 0) {
          Cart::add($productId, max(1, $qty));
      }
      $this->redirect('/cart');
      return '';
  }

  public function update(): string
  {
      \App\Middleware\Csrf::requireToken();
      foreach (($_POST['items'] ?? []) as $key => $qty) {
          Cart::update($key, (int)$qty);
      }
      $this->redirect('/cart');
      return '';
  }

  public function remove(): string
  {
      \App\Middleware\Csrf::requireToken();
      $key = $_POST['key'] ?? '';
      Cart::remove($key);
      $this->redirect('/cart');
      return '';
  }

  public function clear(): string
  {
      \App\Middleware\Csrf::requireToken();
      Cart::clear();
      $this->redirect('/cart');
      return '';
  }
}
PHP;
}

function checkoutControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Config;
use App\Controller;
use App\Models\Order;
use App\Services\Cart;
use App\Services\Payment\Zarinpal;

class CheckoutController extends Controller
{
  public function index(): string
  {
      $totals = Cart::totals();
      if ($totals['total'] <= 0) {
          $this->redirect('/cart');
      }
      return $this->view('checkout', compact('totals'));
  }

  public function placeOrder(): string
  {
      \App\Middleware\Csrf::requireToken();
      $totals = Cart::totals();
      if ($totals['total'] <= 0) {
          $this->redirect('/cart');
      }

      $customer = [
          'email' => $_POST['email'] ?? null,
          'name' => $_POST['name'] ?? null,
          'phone' => $_POST['phone'] ?? null,
          'address' => $_POST['address'] ?? null,
          'city' => $_POST['city'] ?? null,
          'postal_code' => $_POST['postal_code'] ?? null,
      ];

      $items = [];
      foreach ($totals['lines'] as $line) {
          $p = $line['product'];
          $items[] = [
              'product_id' => (int)$p['id'],
              'variation_id' => null,
              'name' => $p['name'],
              'sku' => $p['sku'] ?? null,
              'price' => (int)$line['price'],
              'qty' => (int)$line['qty'],
              'total' => (int)$line['total'],
          ];
      }

      $orderData = array_merge($customer, [
          'subtotal' => $totals['subtotal'],
          'discount' => $totals['discount'],
          'tax' => $totals['tax'],
          'shipping_cost' => $totals['shipping'],
          'total' => $totals['total'],
          'payment_status' => 'unpaid',
          'payment_method' => 'zarinpal',
          'status' => 'pending',
      ]);

      $orderId = (new Order())->create($orderData, $items);

      $callback = rtrim(Config::APP_URL, '/') . '/payment/callback?order_id=' . $orderId;
      $desc = 'پرداخت سفارش #' . $orderId . ' در ' . Config::APP_NAME;
      $req = Zarinpal::requestPayment((int)$totals['total'], $callback, $desc, $customer['email'], $customer['phone']);

      if ($req['success']) {
          header('Location: ' . $req['start_pay']);
          exit;
      }

      return $this->view('checkout', [
          'totals' => $totals,
          'error' => 'خطا در ایجاد تراکنش: ' . ($req['message'] ?? 'نامشخص'),
      ]);
  }

  public function success(string $id): string
  {
      $order = (new \App\Models\Order())->find((int)$id);
      if (!$order) {
          http_response_code(404);
          return 'سفارش یافت نشد';
      }
      return $this->view('order-success', compact('order'));
  }
}
PHP;
}

function paymentControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Controller;
use App\Models\Order;
use App\Services\Payment\Zarinpal;

class PaymentController extends Controller
{
  public function callback(): string
  {
      $orderId = (int)($_GET['order_id'] ?? 0);
      $status = $_GET['Status'] ?? '';
      $authority = $_GET['Authority'] ?? '';
      if ($orderId <= 0 || !$authority) {
          return 'پارامترهای نامعتبر';
      }
      $orderModel = new Order();
      $order = $orderModel->find($orderId);
      if (!$order) {
          return 'سفارش یافت نشد';
      }

      if (strtolower($status) !== 'ok') {
          return 'پرداخت توسط کاربر لغو شد';
      }

      $verify = Zarinpal::verifyPayment((int)$order['total'], $authority);
      if (!empty($verify['success'])) {
          $orderModel->markPaid($orderId, (string)$verify['ref_id']);
          \App\Services\Cart::clear();
          $this->redirect('/order/success/' . $orderId);
          return '';
      }

      if (isset($verify['response']['data']['code']) && (int)$verify['response']['data']['code'] === 101) {
          if ($order['payment_status'] !== 'paid') {
              $orderModel->markPaid($orderId, (string)($verify['response']['data']['ref_id'] ?? ''));
          }
          \App\Services\Cart::clear();
          $this->redirect('/order/success/' . $orderId);
          return '';
      }

      return 'تایید پرداخت ناموفق بود: ' . ($verify['message'] ?? '');
  }
}
PHP;
}

function adminAuthControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers\Admin;

use App\Controller;
use App\Database;

class AuthController extends Controller
{
  public function loginForm(): string
  {
      return $this->view('admin/login');
  }

  public function login(): string
  {
      \App\Middleware\Csrf::requireToken();

      if (!\App\Middleware\RateLimit::allow('login:' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 10)) {
          http_response_code(429);
          exit('درخواست‌های بیش‌ازحد. لطفا چند دقیقه دیگر تلاش کنید.');
      }

      $email = $_POST['email'] ?? '';
      $pass = $_POST['password'] ?? '';
      $db = Database::pdo();
      $stmt = $db->prepare("SELECT * FROM users WHERE email=:email AND role='admin' LIMIT 1");
      $stmt->execute([':email' => $email]);
      $user = $stmt->fetch();
      if ($user && password_verify($pass, $user['password_hash'])) {
          session_regenerate_id(true);
          $_SESSION['admin_id'] = $user['id'];
          $this->redirect('/admin/dashboard');
      }
      return $this->view('admin/login', ['error' => 'ورود نامعتبر']);
  }

  public function logout(): string
  {
      unset($_SESSION['admin_id']);
      $this->redirect('/admin/login');
      return '';
  }
}
PHP;
}

function adminDashboardControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers\Admin;

use App\Controller;
use App\Database;

class DashboardController extends Controller
{
  public function index(): string
  {
      $this->requireAdmin();
      $db = Database::pdo();
      $orders = (int)$db->query("SELECT COUNT(*) AS c FROM orders")->fetch()['c'];
      $products = (int)$db->query("SELECT COUNT(*) AS c FROM products")->fetch()['c'];
      $revenue = (int)$db->query("SELECT COALESCE(SUM(total),0) AS s FROM orders WHERE payment_status='paid'")->fetch()['s'];
      return $this->view('admin/dashboard', compact('orders', 'products', 'revenue'));
  }
}
PHP;
}

function adminProductsControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers\Admin;

use App\Controller;
use App\Models\Product;

class ProductsController extends Controller
{
  public function index(): string
  {
      $this->requireAdmin();
      $products = (new Product())->latest(100);
      return $this->view('admin/products', compact('products'));
  }

  public function create(): string
  {
      $this->requireAdmin();
      \App\Middleware\Csrf::requireToken();
      $data = [
          'name' => $_POST['name'] ?? '',
          'slug' => $_POST['slug'] ?? '',
          'description' => $_POST['description'] ?? '',
          'price' => (int)($_POST['price'] ?? 0),
          'sale_price' => $_POST['sale_price'] ?? '',
          'sku' => $_POST['sku'] ?? null,
          'stock_qty' => (int)($_POST['stock_qty'] ?? 0),
          'status' => $_POST['status'] ?? 'publish',
      ];
      (new Product())->create($data);
      $this->redirect('/admin/products');
      return '';
  }

  public function delete(): string
  {
      $this->requireAdmin();
      \App\Middleware\Csrf::requireToken();
      $id = (int)($_POST['id'] ?? 0);
      if ($id > 0) {
          (new Product())->delete($id);
      }
      $this->redirect('/admin/products');
      return '';
  }
}
PHP;
}

function adminOrdersControllerPhp(): string {
return <<<'PHP'
<?php
declare(strict_types=1);

namespace App\Controllers\Admin;

use App\Controller;
use App\Models\Order;

class OrdersController extends Controller
{
  public function index(): string
  {
      $this->requireAdmin();
      $orders = (new Order())->all(100);
      return $this->view('admin/orders', compact('orders'));
  }

  public function updateStatus(): string
  {
      $this->requireAdmin();
      \App\Middleware\Csrf::requireToken();
      $id = (int)($_POST['id'] ?? 0);
      $status = $_POST['status'] ?? 'processing';
      if ($id > 0) {
          $db = \App\Database::pdo();
          $stmt = $db->prepare("UPDATE orders SET status=:st WHERE id=:id");
          $stmt->execute([':st' => $status, ':id' => $id]);
      }
      $this->redirect('/admin/orders');
      return '';
  }
}
PHP;
}

/* ---------- Views with Tailwind CDN ---------- */

function viewLayoutPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
?>
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<title><?= Helpers::e(\App\Config::APP_NAME) ?></title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="canonical" href="<?= Helpers::e(\App\Config::APP_URL) ?>">
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 text-gray-900">
<header class="bg-white border-b sticky top-0 z-30">
  <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
    <a href="/" class="flex items-center gap-2">
      <div class="w-8 h-8 bg-teal-100 text-teal-600 rounded grid place-items-center font-bold">D</div>
      <span class="font-bold text-lg"><?= Helpers::e(\App\Config::APP_NAME) ?></span>
    </a>
    <nav class="flex items-center gap-4">
      <a class="text-sm hover:text-teal-600" href="/">خانه</a>
      <a class="text-sm hover:text-teal-600" href="/cart">سبد خرید</a>
      <a class="text-sm hover:text-teal-600" href="/admin">مدیریت</a>
    </nav>
  </div>
</header>
<main class="max-w-7xl mx-auto px-4 py-8">
  <?= $content ?? '' ?>
</main>
<footer class="bg-white border-t">
  <div class="max-w-7xl mx-auto px-4 py-6 text-sm text-gray-600 flex flex-col sm:flex-row gap-2 sm:gap-4 items-center justify-between">
    <span><?= Helpers::e(\App\Config::APP_NAME) ?> &copy; <?= date('Y') ?></span>
    <span>فروشگاه‌ساز PHP با پشتیبانی زرین‌پال</span>
    <a href="mailto:<?= Helpers::e(\App\Config::CONTACT_EMAIL) ?>" class="text-teal-600 hover:underline">
      تماس: <?= Helpers::e(\App\Config::CONTACT_EMAIL) ?>
    </a>
  </div>
</footer>
</body>
</html>
PHP;
}

function viewHomePhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
$this->layout = __DIR__ . '/layout.php';
ob_start();
?>
<h1 class="text-2xl font-bold mb-6">محصولات جدید</h1>
<div class="grid gap-6 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
<?php foreach ($products as $p): ?>
  <div class="bg-white border rounded-xl overflow-hidden hover:shadow-sm transition">
    <div class="w-full h-40 bg-gray-100">
      <img alt="product" src="/placeholder.svg" class="w-full h-full object-cover">
    </div>
    <div class="p-4">
      <div class="font-semibold"><?= Helpers::e($p['name']) ?></div>
      <div class="text-gray-600 my-2"><?= Helpers::money((int)($p['sale_price'] ?: $p['price'])) ?></div>
      <a class="inline-flex items-center justify-center px-3 py-2 text-sm bg-teal-600 text-white rounded-lg hover:bg-teal-700" href="/product/<?= Helpers::e($p['slug']) ?>">
        مشاهده
      </a>
    </div>
  </div>
<?php endforeach; ?>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

function viewProductDetailPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
$this->layout = __DIR__ . '/layout.php';
ob_start();
?>
<div class="grid gap-8 md:grid-cols-2">
<div>
  <div class="w-full aspect-square bg-gray-100 rounded-xl overflow-hidden">
    <img alt="product" src="/placeholder.svg" class="w-full h-full object-cover">
  </div>
</div>
<div>
  <h1 class="text-2xl font-bold mb-3"><?= Helpers::e($product['name']) ?></h1>
  <div class="prose prose-sm max-w-none mb-4 prose-p:my-1">
    <?= nl2br(Helpers::e($product['description'])) ?>
  </div>
  <div class="text-xl font-extrabold mb-6"><?= Helpers::money((int)($product['sale_price'] ?: $product['price'])) ?></div>
  <form method="post" action="/cart/add" class="space-y-4">
    <input type="hidden" name="<?= \App\Config::CSRF_TOKEN_KEY ?>" value="<?= Helpers::csrfToken() ?>">
    <input type="hidden" name="product_id" value="<?= (int)$product['id'] ?>">
    <div>
      <label class="block text-sm mb-1">تعداد</label>
      <input type="number" name="qty" min="1" value="1" class="w-28 rounded-lg border-gray-300" />
    </div>
    <button class="inline-flex items-center justify-center px-4 py-2 bg-teal-600 text-white rounded-lg hover:bg-teal-700">
      افزودن به سبد
    </button>
  </form>
</div>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

function viewCartPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
use App\Services\Cart;
$this->layout = __DIR__ . '/layout.php';
ob_start();
$totals = $totals ?? Cart::totals();
?>
<h1 class="text-2xl font-bold mb-6">سبد خرید</h1>

<?php if (empty($totals['lines'])): ?>
<div class="rounded-lg border border-red-200 bg-red-50 text-red-700 p-4">سبد خرید شما خالی است.</div>
<?php else: ?>
<form method="post" action="/cart/update" class="space-y-4">
<input type="hidden" name="<?= \App\Config::CSRF_TOKEN_KEY ?>" value="<?= Helpers::csrfToken() ?>">

<div class="overflow-x-auto bg-white border rounded-xl">
  <table class="w-full text-sm">
    <thead class="bg-gray-50">
      <tr>
        <th class="px-3 py-2 text-right font-semibold">محصول</th>
        <th class="px-3 py-2 text-right font-semibold">قیمت</th>
        <th class="px-3 py-2 text-right font-semibold">تعداد</th>
        <th class="px-3 py-2 text-right font-semibold">مجموع</th>
        <th class="px-3 py-2"></th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($totals['lines'] as $line): $p=$line['product']; ?>
      <tr class="border-t">
        <td class="px-3 py-3"><?= Helpers::e($p['name']) ?></td>
        <td class="px-3 py-3"><?= Helpers::money($line['price']) ?></td>
        <td class="px-3 py-3">
          <input class="w-20 rounded-lg border-gray-300" type="number" name="items[<?= Helpers::e($line['key']) ?>]" value="<?= (int)$line['qty'] ?>" min="1">
        </td>
        <td class="px-3 py-3"><?= Helpers::money($line['total']) ?></td>
        <td class="px-3 py-3 text-left">
          <button
            class="inline-flex items-center justify-center px-3 py-1.5 text-xs bg-red-500 text-white rounded-lg hover:bg-red-600"
            type="submit"
            formaction="/cart/remove"
            name="key"
            value="<?= Helpers::e($line['key']) ?>"
            onclick="return confirm('حذف شود؟')"
          >
            حذف
          </button>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="flex flex-col md:flex-row gap-6">
  <div class="md:w-1/2">
    <h3 class="font-semibold mb-2">کد تخفیف</h3>
    <div class="flex gap-2">
      <input type="text" name="coupon" class="flex-1 rounded-lg border-gray-300" placeholder="مثال: OFF10" />
      <span class="text-gray-500 text-sm self-center">اعمال کوپن در مرحله بعد</span>
    </div>
  </div>
  <div class="md:w-1/2">
    <div class="bg-white border rounded-xl p-4 space-y-2">
      <div class="flex items-center justify-between"><span>جمع جزء</span><span><?= Helpers::money($totals['subtotal']) ?></span></div>
      <div class="flex items-center justify-between"><span>تخفیف</span><span><?= Helpers::money($totals['discount']) ?></span></div>
      <div class="flex items-center justify-between"><span>حمل و نقل</span><span><?= Helpers::money($totals['shipping']) ?></span></div>
      <div class="flex items-center justify-between"><span>مالیات</span><span><?= Helpers::money($totals['tax']) ?></span></div>
      <hr class="my-2">
      <div class="flex items-center justify-between font-bold text-lg"><span>مبلغ قابل پرداخت</span><span><?= Helpers::money($totals['total']) ?></span></div>
      <div class="flex gap-2 pt-2">
        <button class="inline-flex items-center justify-center px-4 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-700" type="submit">به‌روزرسانی سبد</button>
        <a class="inline-flex items-center justify-center px-4 py-2 bg-teal-600 text-white rounded-lg hover:bg-teal-700" href="/checkout">ادامه فرآیند خرید</a>
        <button class="inline-flex items-center justify-center px-4 py-2 bg-gray-100 text-gray-900 rounded-lg hover:bg-gray-200"
                type="submit"
                formaction="/cart/clear"
                onclick="return confirm('سبد خالی شود؟')">
          خالی کردن
        </button>
      </div>
    </div>
  </div>
</div>
</form>
<?php endif; ?>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

function viewCheckoutPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
$this->layout = __DIR__ . '/layout.php';
ob_start();
?>
<h1 class="text-2xl font-bold mb-6">تسویه حساب</h1>
<?php if (!empty($error)): ?>
<div class="rounded-lg border border-red-200 bg-red-50 text-red-700 p-4 mb-4"><?= Helpers::e($error) ?></div>
<?php endif; ?>

<div class="grid gap-6 md:grid-cols-2">
<div class="bg-white border rounded-xl p-4">
  <form method="post" action="/checkout" class="space-y-4">
    <input type="hidden" name="<?= \App\Config::CSRF_TOKEN_KEY ?>" value="<?= Helpers::csrfToken() ?>">
    <div>
      <label class="block text-sm mb-1">نام و نام خانوادگی</label>
      <input name="name" required class="w-full rounded-lg border-gray-300" />
    </div>
    <div>
      <label class="block text-sm mb-1">ایمیل</label>
      <input name="email" type="email" class="w-full rounded-lg border-gray-300" />
    </div>
    <div>
      <label class="block text-sm mb-1">موبایل</label>
      <input name="phone" class="w-full rounded-lg border-gray-300" />
    </div>
    <div>
      <label class="block text-sm mb-1">آدرس</label>
      <textarea name="address" required class="w-full rounded-lg border-gray-300"></textarea>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
      <div>
        <label class="block text-sm mb-1">شهر</label>
        <input name="city" required class="w-full rounded-lg border-gray-300" />
      </div>
      <div>
        <label class="block text-sm mb-1">کد پستی</label>
        <input name="postal_code" required class="w-full rounded-lg border-gray-300" />
      </div>
    </div>
    <button class="inline-flex items-center justify-center px-4 py-2 bg-teal-600 text-white rounded-lg hover:bg-teal-700" type="submit">
      پرداخت با زرین‌پال
    </button>
  </form>
</div>
<div class="bg-white border rounded-xl p-4">
  <h3 class="font-semibold mb-3">سفارش شما</h3>
  <div class="space-y-2 text-sm">
    <div class="flex items-center justify-between"><span>جمع جزء</span><span><?= Helpers::money($totals['subtotal']) ?></span></div>
    <div class="flex items-center justify-between"><span>تخفیف</span><span><?= Helpers::money($totals['discount']) ?></span></div>
    <div class="flex items-center justify-between"><span>حمل و نقل</span><span><?= Helpers::money($totals['shipping']) ?></span></div>
    <div class="flex items-center justify-between"><span>مالیات</span><span><?= Helpers::money($totals['tax']) ?></span></div>
    <hr class="my-2">
    <div class="flex items-center justify-between font-bold text-lg"><span>مبلغ قابل پرداخت</span><span><?= Helpers::money($totals['total']) ?></span></div>
  </div>
</div>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

function viewOrderSuccessPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
$this->layout = __DIR__ . '/layout.php';
ob_start();
?>
<div class="bg-white border rounded-xl p-6 max-w-2xl mx-auto text-center">
<div class="mx-auto w-16 h-16 rounded-full bg-green-100 text-green-600 grid place-items-center text-2xl mb-4">✓</div>
<h1 class="text-2xl font-bold mb-2">پرداخت موفق</h1>
<p class="text-gray-600 mb-4">سفارش شما با موفقیت ثبت شد.</p>
<div class="grid gap-2 text-sm">
  <div>کد سفارش: <span class="font-mono">#<?= (int)$order['id'] ?></span></div>
  <div>وضعیت پرداخت: <?= Helpers::e($order['payment_status']) ?> | وضعیت سفارش: <?= Helpers::e($order['status']) ?></div>
  <div>کدرهگیری: <span class="font-mono"><?= Helpers::e((string)($order['payment_ref'] ?? '')) ?></span></div>
</div>
<a class="inline-flex items-center justify-center px-4 py-2 bg-teal-600 text-white rounded-lg hover:bg-teal-700 mt-6" href="/">
  بازگشت به صفحه اصلی
</a>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

function viewAdminLayoutPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
?>
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<title>مدیریت - <?= Helpers::e(\App\Config::APP_NAME) ?></title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-white">
<header class="border-b border-slate-800">
  <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded bg-teal-400/20 text-teal-400 grid place-items-center font-bold">D</div>
      <span class="font-semibold"><?= Helpers::e(\App\Config::APP_NAME) ?> - مدیریت</span>
    </div>
    <nav class="flex items-center gap-4 text-sm">
      <a href="/admin/dashboard" class="hover:text-teal-400">داشبورد</a>
      <a href="/admin/products" class="hover:text-teal-400">محصولات</a>
      <a href="/admin/orders" class="hover:text-teal-400">سفارش‌ها</a>
      <a href="/admin/logout" class="hover:text-teal-400">خروج</a>
    </nav>
  </div>
</header>
<main class="max-w-7xl mx-auto px-4 py-8">
  <?= $content ?? '' ?>
</main>
</body>
</html>
PHP;
}

function viewAdminLoginPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
ob_start();
?>
<div class="max-w-md mx-auto mt-10 bg-slate-900 border border-slate-800 rounded-xl p-6">
<h2 class="text-xl font-bold mb-4">ورود مدیر</h2>
<?php if (!empty($error)): ?>
  <div class="mb-4 rounded-lg border border-red-400 bg-red-900/30 text-red-200 p-3"><?= Helpers::e($error) ?></div>
<?php endif; ?>
<form method="post" action="/admin/login" class="space-y-4">
  <input type="hidden" name="<?= \App\Config::CSRF_TOKEN_KEY ?>" value="<?= Helpers::csrfToken() ?>">
  <div>
    <label class="block text-sm mb-1">ایمیل</label>
    <input name="email" type="email" required class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" />
  </div>
  <div>
    <label class="block text-sm mb-1">رمز عبور</label>
    <input name="password" type="password" required class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" />
  </div>
  <button class="inline-flex items-center justify-center px-4 py-2 bg-teal-600 text-white rounded-lg hover:bg-teal-700" type="submit">
    ورود
  </button>
</form>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

function viewAdminDashboardPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
ob_start();
?>
<h1 class="text-2xl font-bold mb-6">داشبورد</h1>
<div class="grid gap-4 sm:grid-cols-3">
<div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
  <div class="text-sm text-slate-400 mb-1">تعداد سفارش‌ها</div>
  <div class="text-2xl font-bold"><?= (int)$orders ?></div>
</div>
<div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
  <div class="text-sm text-slate-400 mb-1">تعداد محصولات</div>
  <div class="text-2xl font-bold"><?= (int)$products ?></div>
</div>
<div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
  <div class="text-sm text-slate-400 mb-1">درآمد (پرداخت‌شده)</div>
  <div class="text-2xl font-bold"><?= Helpers::money((int)$revenue) ?></div>
</div>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

function viewAdminProductsPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
ob_start();
?>
<h1 class="text-2xl font-bold mb-6">محصولات</h1>

<div class="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6">
<h3 class="font-semibold mb-4">افزودن محصول</h3>
<form method="post" action="/admin/products/create" class="space-y-4">
  <input type="hidden" name="<?= \App\Config::CSRF_TOKEN_KEY ?>" value="<?= Helpers::csrfToken() ?>">
  <div class="grid gap-4 sm:grid-cols-2">
    <div>
      <label class="block text-sm mb-1">نام</label>
      <input name="name" required class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" />
    </div>
    <div>
      <label class="block text-sm mb-1">اسلاگ</label>
      <input name="slug" required class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" />
    </div>
  </div>
  <div class="grid gap-4 sm:grid-cols-2">
    <div>
      <label class="block text-sm mb-1">قیمت</label>
      <input name="price" type="number" required class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" />
    </div>
    <div>
      <label class="block text-sm mb-1">قیمت فروش ویژه</label>
      <input name="sale_price" type="number" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" />
    </div>
  </div>
  <div class="grid gap-4 sm:grid-cols-2">
    <div>
      <label class="block text-sm mb-1">SKU</label>
      <input name="sku" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" />
    </div>
    <div>
      <label class="block text-sm mb-1">موجودی</label>
      <input name="stock_qty" type="number" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" />
    </div>
  </div>
  <div>
    <label class="block text-sm mb-1">توضیحات</label>
    <textarea name="description" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2"></textarea>
  </div>
  <div>
    <label class="block text-sm mb-1">وضعیت</label>
    <select name="status" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2">
      <option value="publish">انتشار</option>
      <option value="draft">پیش‌نویس</option>
    </select>
  </div>
  <button class="inline-flex items-center justify-center px-4 py-2 bg-teal-600 text-white rounded-lg hover:bg-teal-700" type="submit">
    ذخیره
  </button>
</form>
</div>

<div class="overflow-x-auto bg-slate-900 border border-slate-800 rounded-xl">
<table class="w-full text-sm">
  <thead class="bg-slate-800/60">
    <tr>
      <th class="px-3 py-2 text-right font-semibold">#</th>
      <th class="px-3 py-2 text-right font-semibold">نام</th>
      <th class="px-3 py-2 text-right font-semibold">قیمت</th>
      <th class="px-3 py-2 text-right font-semibold">وضعیت</th>
      <th class="px-3 py-2"></th>
    </tr>
  </thead>
  <tbody>
  <?php foreach ($products as $p): ?>
    <tr class="border-t border-slate-800">
      <td class="px-3 py-2">#<?= (int)$p['id'] ?></td>
      <td class="px-3 py-2"><?= Helpers::e($p['name']) ?></td>
      <td class="px-3 py-2"><?= Helpers::money((int)($p['sale_price'] ?: $p['price'])) ?></td>
      <td class="px-3 py-2"><?= Helpers::e($p['status']) ?></td>
      <td class="px-3 py-2 text-left">
        <form method="post" action="/admin/products/delete" onsubmit="return confirm('حذف شود؟')" class="inline">
          <input type="hidden" name="<?= \App\Config::CSRF_TOKEN_KEY ?>" value="<?= Helpers::csrfToken() ?>">
          <input type="hidden" name="id" value="<?= (int)$p['id'] ?>">
          <button class="inline-flex items-center justify-center px-3 py-1.5 text-xs bg-red-500 text-white rounded-lg hover:bg-red-600">حذف</button>
        </form>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

function viewAdminOrdersPhp(): string {
return <<<'PHP'
<?php
use App\Helpers;
ob_start();
?>
<h1 class="text-2xl font-bold mb-6">سفارش‌ها</h1>
<div class="overflow-x-auto bg-slate-900 border border-slate-800 rounded-xl">
<table class="w-full text-sm">
  <thead class="bg-slate-800/60">
    <tr>
      <th class="px-3 py-2 text-right font-semibold">#</th>
      <th class="px-3 py-2 text-right font-semibold">مبلغ</th>
      <th class="px-3 py-2 text-right font-semibold">وضعیت پرداخت</th>
      <th class="px-3 py-2 text-right font-semibold">وضعیت سفارش</th>
      <th class="px-3 py-2 text-right font-semibold">کدرهگیری</th>
      <th class="px-3 py-2"></th>
    </tr>
  </thead>
  <tbody>
    <?php foreach ($orders as $o): ?>
    <tr class="border-t border-slate-800">
      <td class="px-3 py-2">#<?= (int)$o['id'] ?></td>
      <td class="px-3 py-2"><?= Helpers::money((int)$o['total']) ?></td>
      <td class="px-3 py-2"><?= Helpers::e($o['payment_status']) ?></td>
      <td class="px-3 py-2"><?= Helpers::e($o['status']) ?></td>
      <td class="px-3 py-2"><?= Helpers::e((string)($o['payment_ref'] ?? '')) ?></td>
      <td class="px-3 py-2 text-left">
        <form method="post" action="/admin/orders/status" class="flex items-center gap-2">
          <input type="hidden" name="<?= \App\Config::CSRF_TOKEN_KEY ?>" value="<?= Helpers::csrfToken() ?>">
          <input type="hidden" name="id" value="<?= (int)$o['id'] ?>">
          <select name="status" class="rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-xs">
            <option <?= $o['status']==='processing'?'selected':'' ?> value="processing">در حال انجام</option>
            <option <?= $o['status']==='completed'?'selected':'' ?> value="completed">تکمیل شده</option>
            <option <?= $o['status']==='cancelled'?'selected':'' ?> value="cancelled">لغو شده</option>
          </select>
          <button class="inline-flex items-center justify-center px-3 py-1.5 text-xs bg-teal-600 text-white rounded-lg hover:bg-teal-700" type="submit">
            ذخیره
          </button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </tbody>
</table>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
PHP;
}

/* ---------- اسکیما ---------- */
function schemaSql(): string {
return <<<'SQL'
-- Users
CREATE TABLE IF NOT EXISTS users (
id INT AUTO_INCREMENT PRIMARY KEY,
email VARCHAR(190) NOT NULL UNIQUE,
password_hash VARCHAR(255) NOT NULL,
role ENUM('admin','customer') NOT NULL DEFAULT 'customer',
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Products
CREATE TABLE IF NOT EXISTS products (
id INT AUTO_INCREMENT PRIMARY KEY,
name VARCHAR(255) NOT NULL,
slug VARCHAR(255) NOT NULL UNIQUE,
description TEXT,
price INT NOT NULL,
sale_price INT DEFAULT NULL,
sku VARCHAR(100) DEFAULT NULL,
stock_qty INT DEFAULT 0,
status ENUM('publish','draft') NOT NULL DEFAULT 'publish',
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Coupons
CREATE TABLE IF NOT EXISTS coupons (
id INT AUTO_INCREMENT PRIMARY KEY,
code VARCHAR(100) NOT NULL UNIQUE,
type ENUM('percent','fixed') NOT NULL DEFAULT 'percent',
amount INT NOT NULL,
usage_limit INT DEFAULT NULL,
used INT NOT NULL DEFAULT 0,
expires_at DATETIME DEFAULT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Orders
CREATE TABLE IF NOT EXISTS orders (
id INT AUTO_INCREMENT PRIMARY KEY,
user_id INT DEFAULT NULL,
status VARCHAR(50) NOT NULL DEFAULT 'pending',
total INT NOT NULL,
subtotal INT NOT NULL,
discount INT NOT NULL DEFAULT 0,
shipping_cost INT NOT NULL DEFAULT 0,
tax INT NOT NULL DEFAULT 0,
payment_status VARCHAR(50) NOT NULL DEFAULT 'unpaid',
payment_method VARCHAR(50) DEFAULT 'zarinpal',
payment_ref VARCHAR(100) DEFAULT NULL,
email VARCHAR(190) DEFAULT NULL,
name VARCHAR(190) DEFAULT NULL,
phone VARCHAR(50) DEFAULT NULL,
address TEXT,
city VARCHAR(190) DEFAULT NULL,
postal_code VARCHAR(50) DEFAULT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Order Items
CREATE TABLE IF NOT EXISTS order_items (
id INT AUTO_INCREMENT PRIMARY KEY,
order_id INT NOT NULL,
product_id INT NOT NULL,
variation_id INT DEFAULT NULL,
name VARCHAR(255) NOT NULL,
sku VARCHAR(100) DEFAULT NULL,
price INT NOT NULL,
qty INT NOT NULL,
total INT NOT NULL,
FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Admin seed (admin@example.com / Admin@12345)
INSERT INTO users (email, password_hash, role) VALUES
('admin@example.com', '$2y$10$N9k9F9mPd8j2z8m2B.8ZfO8M1zUq1eI3n7mTgG6s5m3rXJ0k1bC7G', 'admin');

-- Sample product
INSERT INTO products (name, slug, description, price, sale_price, sku, stock_qty, status) VALUES
('محصول نمونه', 'sample-product', 'توضیحات محصول نمونه', 200000, 180000, 'SKU-1', 10, 'publish');
SQL;
}

?>
<!doctype html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>نصاب DIma Shop (PHP/MySQL)</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@3.4.9/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-50 text-gray-900">
<main class="max-w-2xl mx-auto p-6">
  <div class="bg-white border rounded-2xl shadow-sm p-6">
    <h1 class="text-xl font-bold mb-4">نصاب ساده DIma Shop (فقط PHP/MySQL)</h1>

    <?php if ($done): ?>
      <div class="rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-700 p-4 mb-4">
        نصب با موفقیت انجام شد. لطفاً فایل <span class="font-mono">dimashop-installer.php</span> را از روی سرور حذف کنید.
      </div>
      <ul class="list-disc pr-5 space-y-1 text-sm">
        <?php foreach ($log as $l): ?><li><?= h($l) ?></li><?php endforeach; ?>
      </ul>
      <div class="mt-4 space-y-2 text-sm">
        <div>خانه: <a class="text-emerald-700 underline" href="/">/</a></div>
        <div>مدیریت: <span class="font-mono">/admin</span></div>
        <div>Callback زرین‌پال: <span class="font-mono">/payment/callback</span></div>
      </div>
    <?php else: ?>
      <?php if ($errors): ?>
        <div class="rounded-lg border border-red-200 bg-red-50 text-red-700 p-4 mb-4">
          <div class="font-semibold mb-2">خطا:</div>
          <ul class="list-disc pr-5 space-y-1">
            <?php foreach ($errors as $e): ?><li><?= h($e) ?></li><?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <?php if ($log): ?>
        <div class="rounded-lg border border-amber-200 bg-amber-50 text-amber-800 p-4 mb-4">
          <div class="font-semibold mb-2">نکته:</div>
          <ul class="list-disc pr-5 space-y-1">
            <?php foreach ($log as $l): ?><li><?= h($l) ?></li><?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <form method="post" class="space-y-6">
        <input type="hidden" name="_csrf" value="<?= h($csrf) ?>">

        <div>
          <h2 class="font-semibold mb-3">اتصال دیتابیس</h2>
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label class="block text-sm mb-1">DB Host</label>
              <input name="db_host" value="<?= h($_POST['db_host'] ?? $defaults['db_host']) ?>" class="w-full rounded-lg border-gray-300">
            </div>
            <div>
              <label class="block text-sm mb-1">DB Name</label>
              <input name="db_name" value="<?= h($_POST['db_name'] ?? $defaults['db_name']) ?>" class="w-full rounded-lg border-gray-300">
            </div>
            <div>
              <label class="block text-sm mb-1">DB User</label>
              <input name="db_user" value="<?= h($_POST['db_user'] ?? $defaults['db_user']) ?>" class="w-full rounded-lg border-gray-300">
            </div>
            <div>
              <label class="block text-sm mb-1">DB Pass</label>
              <input name="db_pass" type="password" value="<?= h($_POST['db_pass'] ?? $defaults['db_pass']) ?>" class="w-full rounded-lg border-gray-300">
            </div>
          </div>
        </div>

        <div>
          <h2 class="font-semibold mb-3">تنظیمات اپلیکیشن</h2>
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label class="block text-sm mb-1">APP URL</label>
              <input name="app_url" value="<?= h($_POST['app_url'] ?? $defaults['app_url']) ?>" class="w-full rounded-lg border-gray-300" placeholder="https://example.com">
            </div>
            <div>
              <label class="block text-sm mb-1">ایمیل پشتیبانی</label>
              <input name="contact_email" value="<?= h($_POST['contact_email'] ?? $defaults['contact_email']) ?>" class="w-full rounded-lg border-gray-300">
            </div>
          </div>
        </div>

        <div>
          <h2 class="font-semibold mb-3">زرین‌پال</h2>
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label class="block text-sm mb-1">Merchant ID</label>
              <input name="merchant_id" value="<?= h($_POST['merchant_id'] ?? $defaults['merchant_id']) ?>" class="w-full rounded-lg border-gray-300">
            </div>
            <div>
              <label class="block text-sm mb-1">Sandbox</label>
              <select name="sandbox" class="w-full rounded-lg border-gray-300">
                <?php $sb = (string)($_POST['sandbox'] ?? $defaults['sandbox']); ?>
                <option value="1" <?= $sb==='1'?'selected':'' ?>>فعال</option>
                <option value="0" <?= $sb==='0'?'selected':'' ?>>غیرفعال (Production)</option>
              </select>
            </div>
          </div>
        </div>

        <div>
          <h2 class="font-semibold mb-3">مدیریت</h2>
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label class="block text-sm mb-1">ایمیل مدیر</label>
              <input name="admin_email" type="email" value="<?= h($_POST['admin_email'] ?? $defaults['admin_email']) ?>" class="w-full rounded-lg border-gray-300">
            </div>
            <div>
              <label class="block text-sm mb-1">رمز عبور مدیر</label>
              <input name="admin_password" type="password" value="<?= h($_POST['admin_password'] ?? '') ?>" class="w-full rounded-lg border-gray-300">
            </div>
          </div>
          <p class="text-xs text-gray-500 mt-2">اگر رمز عبور وارد نشود، کاربر مدیر پیش‌فرض تغییر نمی‌کند.</p>
        </div>

        <div class="flex items-center gap-3">
          <button class="inline-flex items-center justify-center px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700" type="submit">نصب</button>
          <a class="text-sm text-gray-600 hover:underline" href="/">بازگشت به سایت</a>
        </div>
      </form>
    <?php endif; ?>
  </div>

  <p class="text-xs text-gray-500 mt-4">پس از اتمام نصب، برای امنیت، فایل dimashop-installer.php را حذف کنید.</p>
</main>
</body>
</html>