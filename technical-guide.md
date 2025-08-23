# راهنمای تکنیکی دیما شاپ

## 🏗️ معماری سیستم

### ساختار کلی
دیما شاپ از معماری MVC ساده و کارآمدی استفاده می‌کند که شامل:

- **Model**: کلاس‌های `lib/` برای دسترسی به داده
- **View**: فایل‌های قالب در `theme/default/`
- **Controller**: فایل‌های `admin/pages/` و `index.php`

### کلاس‌های اصلی

#### 1. Settings Class
```php
class Settings {
    public static function getInstance(): Settings
    public function get(string $key, $default = null)
    public function set(string $key, $value): void
    public function getBool(string $key, bool $default = false): bool
    public function getInt(string $key, int $default = 0): int
}
```

#### 2. SecurityFirewall Class
```php
class SecurityFirewall {
    public function setMaxRequestsPerMinute(int $max): SecurityFirewall
    public function setMaxFailedAttempts(int $max): SecurityFirewall
    public function checkRequest(): bool
    public function blockIP(string $ip): void
    public function isIPBlocked(string $ip): bool
}
```

#### 3. AIHelper Class
```php
class AIHelper {
    public static function getInstance(): AIHelper
    public function generateProductDescription(string $title, ...): string
    public function generateBlogPost(string $title, ...): string
    public function chat(string $message, array $history): array
    public function analyzeImage(string $imagePath, string $question): array
}
```

#### 4. SimpleRouter Class
```php
class SimpleRouter {
    public static function getInstance(): SimpleRouter
    public function url(string $page, array $params = []): string
    public function shopUrl(string $category = null): string
    public function productUrl(string $category, string $slug): string
    public function adminUrl(string $section = 'dashboard'): string
}
```

## 🔐 سیستم امنیت

### فایروال امنیتی
سیستم فایروال چندلایه شامل:

1. **Rate Limiting**: محدودیت تعداد درخواست در دقیقه
2. **IP Blocking**: مسدودسازی IP های مشکوک
3. **Pattern Detection**: تشخیص الگوهای حمله
4. **Logging**: ثبت تمام فعالیت‌های مشکوک

### محافظت در برابر حملات

#### SQL Injection
```php
// استفاده از PDO Prepared Statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);
```

#### XSS Protection
```php
// استفاده از htmlspecialchars
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
```

#### CSRF Protection
```php
// تولید توکن CSRF
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

// بررسی توکن
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token validation failed');
}
```

## 🤖 سیستم هوش مصنوعی

### تنظیمات API
```php
// در admin/pages/ai-settings.php
$ai = AIHelper::getInstance();
$ai->setApiToken('your-talkbot-api-token');
```

### تولید محتوا
```php
// تولید توضیحات محصول
$description = $ai->generateProductDescription(
    'لپ تاپ گیمینگ',
    'لپ تاپ قدرتمند برای بازی',
    'الکترونیک',
    ['پردازنده قوی', 'کارت گرافیک عالی']
);

// تولید مقاله بلاگ
$article = $ai->generateBlogPost(
    'بهترین لپ تاپ‌های 2024',
    'لپ تاپ, گیمینگ, تکنولوژی',
    'professional',
    1000
);
```

### چت هوشمند
```php
// شروع چت
$result = $ai->chat('سلام، می‌خواهم محصولی بخرم', []);

if ($result['success']) {
    $response = $result['response'];
    $conversation = $result['conversation'];
}
```

### تحلیل تصاویر
```php
// تحلیل تصویر محصول
$analysis = $ai->analyzeImage(
    '/path/to/image.jpg',
    'این تصویر چه محصولی را نشان می‌دهد؟'
);
```

## 🗄️ پایگاه داده

### ساختار جداول اصلی

#### جدول products
```sql
CREATE TABLE products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    short_description TEXT,
    price DECIMAL(10,2) NOT NULL,
    sale_price DECIMAL(10,2),
    stock_quantity INT DEFAULT 0,
    category_id INT,
    featured BOOLEAN DEFAULT FALSE,
    status ENUM('active','inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);
```

#### جدول orders
```sql
CREATE TABLE orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    order_number VARCHAR(50) UNIQUE NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    status ENUM('pending','paid','shipped','completed','cancelled') DEFAULT 'pending',
    payment_method VARCHAR(50),
    shipping_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### کوئری‌های بهینه

#### آمار فروش ماهانه
```sql
SELECT 
    DATE_FORMAT(created_at, '%Y-%m') AS month,
    SUM(total) AS total_sales,
    COUNT(*) AS order_count
FROM orders 
WHERE status IN ('paid','shipped','completed')
  AND created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
GROUP BY month 
ORDER BY month ASC;
```

#### محصولات پرفروش
```sql
SELECT 
    p.title,
    p.slug,
    SUM(oi.qty) as total_quantity,
    SUM(oi.qty * oi.unit_price) as total_revenue
FROM order_items oi
JOIN products p ON p.id = oi.product_id
JOIN orders o ON o.id = oi.order_id 
WHERE o.status IN ('paid','shipped','completed')
GROUP BY p.id
ORDER BY total_revenue DESC
LIMIT 10;
```

## 🎨 سیستم قالب‌ها

### ساختار قالب
```
theme/default/
├── assets/
│   ├── css/          # استایل‌ها
│   ├── js/           # اسکریپت‌ها
│   ├── images/       # تصاویر
│   └── fonts/        # فونت‌ها
├── include/          # فایل‌های مشترک
├── widget/           # ویجت‌ها
└── *.php            # صفحات اصلی
```

### فایل‌های مشترک
- `include/header.php` - هدر مشترک
- `include/footer.php` - فوتر مشترک
- `include/navbar.php` - منوی ناوبری

### ویجت‌ها
- `widget/slider.php` - اسلایدر محصولات
- `widget/category.php` - نمایش دسته‌بندی‌ها
- `widget/product.php` - نمایش محصولات

## 📱 API ها

### جستجوی محصولات
```php
// GET /api/search.php?q=لپ‌تاپ&category=الکترونیک
$query = $_GET['q'] ?? '';
$category = $_GET['category'] ?? '';

$sql = "SELECT * FROM products WHERE status = 'active'";
if ($query) {
    $sql .= " AND (title LIKE ? OR description LIKE ?)";
    $params[] = "%$query%";
    $params[] = "%$query%";
}
if ($category) {
    $sql .= " AND category_id = (SELECT id FROM categories WHERE slug = ?)";
    $params[] = $category;
}
```

### مدیریت سبد خرید
```php
// POST /api/cart.php
$action = $_POST['action'] ?? '';
$productId = (int)($_POST['product_id'] ?? 0);
$quantity = (int)($_POST['quantity'] ?? 1);

switch ($action) {
    case 'add':
        addToCart($productId, $quantity);
        break;
    case 'update':
        updateCartItem($productId, $quantity);
        break;
    case 'remove':
        removeFromCart($productId);
        break;
}
```

## 🔧 توسعه و سفارشی‌سازی

### افزودن ویژگی جدید

#### 1. ایجاد کلاس جدید
```php
// lib/new_feature.php
class NewFeature {
    private $settings;
    
    public function __construct() {
        $this->settings = Settings::getInstance();
    }
    
    public function doSomething(): string {
        return "Feature implemented!";
    }
}
```

#### 2. بارگذاری در config.php
```php
// config.php
require_once lib_file('new_feature.php');
```

#### 3. ایجاد صفحه مدیریت
```php
// admin/pages/new-feature.php
require_once __DIR__ . '/../includes/header.php';

$feature = new NewFeature();
$result = $feature->doSomething();
?>

<div class="container-fluid">
    <h1>ویژگی جدید</h1>
    <p><?php echo $result; ?></p>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
```

### تغییر قالب

#### اضافه کردن استایل جدید
```css
/* theme/default/assets/css/custom.css */
.custom-button {
    @apply bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded;
}

.custom-card {
    @apply bg-white rounded-lg shadow-md p-6;
}
```

#### اضافه کردن اسکریپت جدید
```javascript
// theme/default/assets/js/custom.js
document.addEventListener('DOMContentLoaded', function() {
    // کد جاوااسکریپت شما
    console.log('Custom script loaded!');
});
```

## 📊 بهینه‌سازی عملکرد

### کش کردن
```php
// کش کردن نتایج کوئری
$cacheKey = "products_category_{$categoryId}";
$cached = cache_get($cacheKey);

if ($cached === false) {
    $products = $pdo->query("SELECT * FROM products WHERE category_id = $categoryId")->fetchAll();
    cache_set($cacheKey, $products, 3600); // 1 ساعت
} else {
    $products = $cached;
}
```

### فشرده‌سازی تصاویر
```php
// فشرده‌سازی تصاویر آپلود شده
function compressImage($source, $destination, $quality = 80) {
    $info = getimagesize($source);
    
    if ($info['mime'] == 'image/jpeg') {
        $image = imagecreatefromjpeg($source);
    } elseif ($info['mime'] == 'image/png') {
        $image = imagecreatefrompng($source);
    }
    
    imagejpeg($image, $destination, $quality);
    imagedestroy($image);
}
```

### بهینه‌سازی CSS/JS
```bash
# فشرده‌سازی CSS
npx cssnano input.css -o output.min.css

# فشرده‌سازی JavaScript
npx terser input.js -o output.min.js
```

## 🧪 تست و دیباگ

### لاگ‌گیری
```php
// لاگ‌گیری خطاها
function logError($message, $context = []) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'message' => $message,
        'context' => $context,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ];
    
    file_put_contents(
        'logs/errors.log',
        json_encode($logEntry) . "\n",
        FILE_APPEND | LOCK_EX
    );
}
```

### تست عملکرد
```php
// اندازه‌گیری زمان اجرا
$startTime = microtime(true);

// کد شما
$result = expensiveOperation();

$endTime = microtime(true);
$executionTime = ($endTime - $startTime) * 1000; // میلی‌ثانیه

logError("Operation took {$executionTime}ms");
```

## 🚀 استقرار

### تنظیمات تولید
```php
// config.php
if ($_SERVER['HTTP_HOST'] === 'production.com') {
    // تنظیمات تولید
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    error_reporting(E_ALL);
} else {
    // تنظیمات توسعه
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
}
```

### فایل .htaccess
```apache
# mod_rewrite برای URL های زیبا
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?page=$1 [QSA,L]

# امنیت
<Files "*.php">
    Order Allow,Deny
    Allow from all
</Files>

# فشرده‌سازی
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>
```

---

این راهنمای تکنیکی به شما کمک می‌کند تا سیستم دیما شاپ را بهتر درک کرده و ویژگی‌های جدیدی به آن اضافه کنید.
