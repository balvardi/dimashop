# راهنمای نصب و راه‌اندازی دیما شاپ

## 📋 پیش‌نیازها

### سرور وب
- **Apache 2.4+** یا **Nginx 1.18+**
- **mod_rewrite** فعال (برای Apache)
- **SSL Certificate** (توصیه می‌شود)

### نرم‌افزار
- **PHP 8.0+** با افزونه‌های زیر:
  - `pdo_mysql`
  - `gd` (برای پردازش تصاویر)
  - `curl` (برای API ها)
  - `json`
  - `mbstring`
  - `openssl`
  - `zip` (برای بک‌آپ)

### پایگاه داده
- **MySQL 5.7+** یا **MariaDB 10.2+**
- کاربر با دسترسی کامل به پایگاه داده

### حداقل مشخصات سرور
- **RAM**: 512MB
- **CPU**: 1 Core
- **فضای دیسک**: 2GB
- **پهنای باند**: نامحدود

## 🚀 مراحل نصب

### مرحله 1: آماده‌سازی فایل‌ها

#### دانلود و استخراج
```bash
# دانلود آخرین نسخه
wget https://github.com/dimashop/dimashop/releases/latest/download/dimashop.zip

# استخراج فایل‌ها
unzip dimashop.zip

# انتقال به پوشه وب‌سرور
sudo mv dimashop /var/www/html/
sudo chown -R www-data:www-data /var/www/html/dimashop
sudo chmod -R 755 /var/www/html/dimashop
```

#### تنظیم مجوزها
```bash
# تنظیم مجوزهای پوشه uploads
sudo chmod -R 777 /var/www/html/dimashop/uploads/
sudo chmod -R 777 /var/www/html/dimashop/logs/

# تنظیم مجوزهای فایل‌های مهم
sudo chmod 644 /var/www/html/dimashop/config.php
sudo chmod 644 /var/www/html/dimashop/.htaccess
```

### مرحله 2: ایجاد پایگاه داده

#### ورود به MySQL
```bash
mysql -u root -p
```

#### ایجاد پایگاه داده
```sql
-- ایجاد پایگاه داده
CREATE DATABASE dima_shop CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ایجاد کاربر
CREATE USER 'dimashop_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';

-- اعطای دسترسی
GRANT ALL PRIVILEGES ON dima_shop.* TO 'dimashop_user'@'localhost';
FLUSH PRIVILEGES;

-- خروج
EXIT;
```

### مرحله 3: اجرای نصب کننده

#### دسترسی به نصب کننده
1. مرورگر خود را باز کنید
2. به آدرس `http://your-domain.com/dimashop/install/` بروید
3. صفحه نصب کننده نمایش داده می‌شود

#### مراحل نصب
1. **بررسی پیش‌نیازها**
   - تأیید نسخه PHP
   - تأیید افزونه‌های مورد نیاز
   - تأیید مجوزهای پوشه‌ها

2. **تنظیمات پایگاه داده**
   ```
   Host: localhost
   Database: dima_shop
   Username: dimashop_user
   Password: StrongPassword123!
   Port: 3306
   ```

3. **تنظیمات مدیر**
   ```
   Admin Email: admin@yourdomain.com
   Admin Password: AdminPass123!
   Admin Name: مدیر سیستم
   ```

4. **تنظیمات سایت**
   ```
   Site Name: دیما شاپ
   Site URL: http://yourdomain.com/dimashop/
   Admin Email: admin@yourdomain.com
   Timezone: Asia/Tehran
   ```

5. **نصب و راه‌اندازی**
   - کلیک روی "نصب سیستم"
   - انتظار برای تکمیل نصب
   - تأیید نصب موفق

### مرحله 4: تنظیمات پس از نصب

#### حذف پوشه نصب
```bash
sudo rm -rf /var/www/html/dimashop/install/
```

#### تنظیم فایل .htaccess
```apache
# /var/www/html/dimashop/.htaccess
RewriteEngine On

# امنیت
<Files "config.php">
    Order Allow,Deny
    Deny from all
</Files>

<Files "*.sql">
    Order Allow,Deny
    Deny from all
</Files>

# URL های زیبا
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?page=$1 [QSA,L]

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

# کش مرورگر
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access plus 1 month"
    ExpiresByType image/jpeg "access plus 1 month"
    ExpiresByType image/gif "access plus 1 month"
    ExpiresByType image/png "access plus 1 month"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/pdf "access plus 1 month"
    ExpiresByType text/javascript "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType application/x-javascript "access plus 1 month"
    ExpiresByType application/x-shockwave-flash "access plus 1 month"
    ExpiresByType image/x-icon "access plus 1 year"
    ExpiresDefault "access plus 2 days"
</IfModule>
```

#### تنظیم SSL (HTTPS)
```apache
# /etc/apache2/sites-available/dimashop.conf
<VirtualHost *:80>
    ServerName yourdomain.com
    Redirect permanent / https://yourdomain.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName yourdomain.com
    DocumentRoot /var/www/html/dimashop
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/yourdomain.com/privkey.pem
    
    <Directory /var/www/html/dimashop>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

## ⚙️ تنظیمات سیستم

### مرحله 5: تنظیمات اولیه

#### ورود به پنل مدیریت
1. به آدرس `http://yourdomain.com/dimashop/admin/` بروید
2. با اطلاعات مدیر وارد شوید
3. به بخش "تنظیمات" بروید

#### تنظیمات عمومی
```
Site Name: نام فروشگاه شما
Site Description: توضیحات فروشگاه
Site Keywords: کلمات کلیدی SEO
Site Logo: آپلود لوگو
Favicon: آپلود آیکون سایت
```

#### تنظیمات تماس
```
Contact Email: info@yourdomain.com
Contact Phone: شماره تماس
Contact Address: آدرس فیزیکی
Working Hours: ساعات کاری
```

#### تنظیمات پرداخت
```
Payment Gateway: ZarinPal
ZarinPal Merchant ID: کد درگاه شما
Test Mode: فعال (برای تست)
```

### مرحله 6: تنظیمات AI

#### تنظیم Talkbot API
1. به بخش "تنظیمات AI" بروید
2. توکن API خود را وارد کنید
3. تنظیمات مدل را بررسی کنید
4. تست اتصال را انجام دهید

#### تنظیمات پیشرفته AI
```
Model: gpt-4o-mini
Temperature: 0.3
Max Tokens: 4000
Language: Persian
```

### مرحله 7: تنظیمات امنیت

#### فایروال امنیتی
```
Security Enabled: فعال
Max Requests Per Minute: 100
Max Failed Attempts: 5
Block Suspicious IPs: فعال
Log Security Events: فعال
```

#### تنظیمات جلسه
```
Session Timeout: 3600 (1 ساعت)
Secure Cookies: فعال (برای HTTPS)
HTTP Only Cookies: فعال
```

## 🔧 بهینه‌سازی

### مرحله 8: بهینه‌سازی عملکرد

#### کش کردن
```php
// در config.php
define('CACHE_ENABLED', true);
define('CACHE_DURATION', 3600);
define('CACHE_PATH', __DIR__ . '/cache/');
```

#### فشرده‌سازی تصاویر
```bash
# نصب ImageMagick
sudo apt-get install imagemagick

# تنظیم مجوزها
sudo chmod 755 /usr/bin/convert
```

#### بهینه‌سازی پایگاه داده
```sql
-- بهینه‌سازی جداول
OPTIMIZE TABLE products, orders, users, categories;

-- ایجاد ایندکس‌های مهم
CREATE INDEX idx_products_status ON products(status);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_created ON orders(created_at);
```

### مرحله 9: پشتیبان‌گیری

#### اسکریپت پشتیبان‌گیری خودکار
```bash
#!/bin/bash
# /root/backup_dimashop.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/dimashop"
SITE_DIR="/var/www/html/dimashop"
DB_NAME="dima_shop"
DB_USER="dimashop_user"
DB_PASS="StrongPassword123!"

# ایجاد پوشه پشتیبان
mkdir -p $BACKUP_DIR

# پشتیبان‌گیری از فایل‌ها
tar -czf $BACKUP_DIR/files_$DATE.tar.gz -C $SITE_DIR .

# پشتیبان‌گیری از پایگاه داده
mysqldump -u$DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/db_$DATE.sql

# فشرده‌سازی پایگاه داده
gzip $BACKUP_DIR/db_$DATE.sql

# حذف فایل‌های قدیمی (بیش از 30 روز)
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

#### تنظیم Cron Job
```bash
# ویرایش crontab
crontab -e

# اضافه کردن پشتیبان‌گیری روزانه
0 2 * * * /root/backup_dimashop.sh >> /var/log/backup.log 2>&1
```

## 🧪 تست سیستم

### مرحله 10: تست عملکرد

#### تست امنیت
1. **تست SQL Injection**
   ```
   http://yourdomain.com/dimashop/search?q=' OR 1=1--
   ```

2. **تست XSS**
   ```
   http://yourdomain.com/dimashop/search?q=<script>alert('XSS')</script>
   ```

3. **تست CSRF**
   - بررسی وجود توکن CSRF در فرم‌ها
   - تست ارسال فرم بدون توکن

#### تست عملکرد
1. **تست سرعت بارگذاری**
   - استفاده از Google PageSpeed Insights
   - تست با GTmetrix

2. **تست پایگاه داده**
   - بررسی زمان اجرای کوئری‌ها
   - بررسی استفاده از ایندکس‌ها

#### تست ویژگی‌ها
1. **تست ثبت‌نام و ورود**
2. **تست افزودن محصول**
3. **تست سبد خرید**
4. **تست پرداخت**
5. **تست سیستم AI**

## 🚨 رفع مشکلات رایج

### مشکل 1: خطای 500
```bash
# بررسی لاگ‌های خطا
sudo tail -f /var/log/apache2/error.log

# بررسی مجوزهای فایل‌ها
sudo chown -R www-data:www-data /var/www/html/dimashop
sudo chmod -R 755 /var/www/html/dimashop
```

### مشکل 2: خطای اتصال پایگاه داده
```bash
# بررسی سرویس MySQL
sudo systemctl status mysql

# بررسی تنظیمات اتصال
sudo nano /var/www/html/dimashop/config.php
```

### مشکل 3: خطای mod_rewrite
```bash
# فعال‌سازی mod_rewrite
sudo a2enmod rewrite
sudo systemctl restart apache2

# بررسی تنظیمات .htaccess
sudo nano /var/www/html/dimashop/.htaccess
```

### مشکل 4: خطای مجوزها
```bash
# تنظیم مجوزهای صحیح
sudo chown -R www-data:www-data /var/www/html/dimashop
sudo chmod -R 755 /var/www/html/dimashop
sudo chmod -R 777 /var/www/html/dimashop/uploads/
sudo chmod -R 777 /var/www/html/dimashop/logs/
```

## 📚 منابع مفید

### مستندات رسمی
- [مستندات PHP](https://www.php.net/docs.php)
- [مستندات MySQL](https://dev.mysql.com/doc/)
- [مستندات Apache](https://httpd.apache.org/docs/)

### انجمن‌های پشتیبانی
- [Stack Overflow](https://stackoverflow.com/)
- [GitHub Issues](https://github.com/dimashop/dimashop/issues)

### ابزارهای مفید
- [Let's Encrypt](https://letsencrypt.org/) - گواهی SSL رایگان
- [GTmetrix](https://gtmetrix.com/) - تست عملکرد
- [Google PageSpeed Insights](https://pagespeed.web.dev/) - بهینه‌سازی سرعت

---

با دنبال کردن این راهنما، سیستم دیما شاپ شما به درستی نصب و راه‌اندازی خواهد شد. در صورت بروز مشکل، لاگ‌های سیستم را بررسی کرده و از انجمن‌های پشتیبانی کمک بگیرید.
