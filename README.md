# Dima Shop

Dima Shop یک فروشگاه‌ساز رایگان، سبک و ماژولار با PHP و MySQL است که از درگاه پرداخت زرین‌پال پشتیبانی می‌کند و رابط کاربری آن با Tailwind CSS ساخته شده است. هدف، ارائه‌ی یک هسته‌ی امن و توسعه‌پذیر شبیه فروشگاه‌سازهایی مانند WooCommerce است.

- معماری: MVC سبک با Router سفارشی
- پایگاه‌داده: MySQL با PDO و کوئری‌های آماده (Prepared)
- پرداخت: زرین‌پال (Request/Verify + Callback)
- رابط کاربری: Tailwind CSS (CDN) با RTL
- سبد خرید: مبتنی بر Session با جمع‌کل، تخفیف، مالیات و حمل‌ونقل پایه
- پنل مدیریت: ورود مدیر، مدیریت محصولات و سفارش‌ها
- امنیت: CSRF برای همه فرم‌های POST، XSS escape، سیاست‌های .htaccess
- توسعه‌پذیری: سیستم Hooks ساده برای Actions/Filters

---

## فهرست مطالب

- نصب سریع
- تنظیمات
- نیازمندی‌ها
- ساختار پوشه‌ها
- مسیرها (Routes)
- پرداخت زرین‌پال
- امنیت و انتشار Production
- سفارشی‌سازی Tailwind
- نقشه راه (Roadmap)
- مشارکت
- مجوز

---

## نصب سریع

1) کلون مخزن
- `git clone https://github.com/balvardi/Dimashop.git`
- DocumentRoot وب‌سرور را روی پوشه `public` تنظیم کنید.

2) پایگاه‌داده
- یک دیتابیس MySQL بسازید.
- فایل `database/schema.sql` را اجرا کنید.
- کاربر مدیر پیش‌فرض: ایمیل `admin@example.com`، رمز `Admin@12345`.

3) پیکربندی برنامه
- فایل `app/Config.php` را ویرایش کنید:
  - `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`
  - `APP_URL` (بدون اسلش انتهایی، مثال: `https://your-domain.com`)
  - `APP_NAME = "Dima Shop"`
  - `ZARINPAL_MERCHANT_ID` (مرچنت زرین‌پال)
  - `ZARINPAL_SANDBOX` (true برای تست، false برای عملیاتی)
  - `ZARINPAL_AMOUNT_IN_RIAL` (true اگر مبلغ را باید به ریال ارسال کنید)

4) وب‌سرور
- Apache: فایل `public/.htaccess` شامل قوانین Rewrite و هدرهای امنیتی است.
- Nginx (نمونه کانفیگ):
  ```
  server {
    listen 80;
    server_name your-domain.com;
    root /path/to/Dimashop/public;

    index index.php index.html;
    location / {
      try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
      include snippets/fastcgi-php.conf;
      fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
      fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
      include fastcgi_params;
    }

    location ~* \.(sql|env|log|bak|ini)$ { deny all; }
  }
  ```

5) تنظیم Callback زرین‌پال
- در پنل زرین‌پال، Callback URL را روی `{APP_URL}/payment/callback` قرار دهید.
- مثال: `https://your-domain.com/payment/callback`

---

## تنظیمات

- `app/Config.php`:
  - `APP_NAME`: نام فروشگاه (به‌صورت پیش‌فرض `Dima Shop`)
  - `APP_URL`: آدرس اصلی سایت (برای ریدایرکت‌ها و Callback)
  - `CURRENCY`: `Toman` یا `Rial`
  - `ZARINPAL_AMOUNT_IN_RIAL`: اگر زرین‌پال شما مبلغ را به ریال می‌پذیرد `true` بگذارید تا مبلغ تومانی در 10 ضرب شود.
  - `ZARINPAL_MERCHANT_ID`: مرچنت زرین‌پال
  - `ZARINPAL_SANDBOX`: حالت تست/عملیاتی

توصیه امنیتی: اسرار را در مخزن قرار ندهید. می‌توانید از `.env` استفاده کنید و فایل `.env.example` بسازید. سپس برای بارگذاری متغیرها از کتابخانه‌های `vlucas/phpdotenv` استفاده نمایید.

---

## نیازمندی‌ها

- PHP 8.1 یا جدیدتر (PDO، cURL فعال)
- MySQL 5.7+ یا 8.0+
- Apache/Nginx
- OpenSSL/HTTPS برای محیط عملیاتی

---

## ساختار پوشه‌ها

```
app/
  Controllers/
    Admin/
  Middleware/
  Models/
  Services/
    Payment/
  Views/
    admin/
  Config.php
  Database.php
  Router.php
  Controller.php
  Model.php
  Helpers.php
database/
  schema.sql
public/
  index.php
  .htaccess
  uploads/   (حاوی .htaccess برای جلوگیری از اجرای PHP)
```

---

## مسیرها (Routes)

- فروشگاه:
  - `GET /` صفحه اصلی
  - `GET /product/{slug}` صفحه محصول
  - `GET /cart` سبد خرید
  - `POST /cart/add|update|remove|clear` مدیریت سبد
  - `GET /checkout` تسویه حساب
  - `POST /checkout` ثبت سفارش و انتقال به پرداخت
  - `GET /payment/callback` بازگشت از زرین‌پال
  - `GET /order/success/{id}` نتیجه موفق

- مدیریت:
  - `GET /admin/login`, `POST /admin/login`, `GET /admin/logout`
  - `GET /admin/dashboard`
  - `GET /admin/products`, `POST /admin/products/create|delete`
  - `GET /admin/orders`, `POST /admin/orders/status`

تمام مسیرهای Admin نیاز به ورود مدیر دارند.

---

## پرداخت زرین‌پال

جریان پرداخت:
1) کاربر در `/checkout` اطلاعات را ثبت می‌کند.
2) سفارش در DB با `payment_status = unpaid` ایجاد می‌شود.
3) درخواست پرداخت زرین‌پال (`request`) و ریدایرکت به `StartPay`.
4) پس از بازگشت کاربر، در `/payment/callback`:
   - بررسی `Status` و `Authority`
   - `verify` با مبلغ دقیق ثبت‌شده در سفارش
   - در صورت موفقیت، `payment_status = paid` و تغییر وضعیت سفارش

نکته مهم: مبلغ را از DB بخوانید و با پیکربندی `ZARINPAL_AMOUNT_IN_RIAL` هماهنگ کنید. با `code=100` موفق و `code=101` (already verified) را idempotent مدیریت کنید.

---

## امنیت و انتشار Production

بررسی‌های کلیدی:
- خطاها:
  - `APP_DEBUG = false` در Production
  - غیرفعال کردن نمایش خطا و فعال کردن لاگ امن
- Session:
  - `session.cookie_httponly = 1`
  - `session.cookie_secure = 1` روی HTTPS
  - `session.cookie_samesite = Lax`
  - `session_regenerate_id(true)` بعد از ورود موفق
- CSRF:
  - تمام فرم‌های POST دارای `<input type="hidden" name="_csrf" ...>`
  - اعتبارسنجی سمت سرور برای همه اکشن‌ها
- XSS:
  - تمام خروجی‌ها با `Helpers::e()` فرار داده شوند
- SQLi:
  - فقط Prepared Statements
- .htaccess و هدرهای امنیتی:
  - `Options -Indexes`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Security-Policy` متناسب با دامنه شما (Tailwind CDN لحاظ شود)
  - HSTS فقط روی HTTPS
- آپلودها:
  - جلوگیری از اجرای PHP در `public/uploads` (فایل `.htaccess` اختصاصی)
  - اعتبارسنجی MIME/اندازه، نام‌گذاری تصادفی
- احراز هویت:
  - عدم افشای تمایز خطای ایمیل/رمز
  - محدودیت تلاش ورود و CAPTCHA بعد از چند تلاش
- نرخ‌دهی:
  - Rate Limit روی `/admin/login`، `/checkout`، `/payment/callback`

نمونه `.htaccess` برای `public/uploads`:
```
php_flag engine off
RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8
RemoveType .php .phtml .php3 .php4 .php5 .php7 .php8
<FilesMatch "\.(php|phtml|php\d+)$">
  Require all denied
</FilesMatch>
Options -ExecCGI
```

---

## سفارشی‌سازی Tailwind

پیش‌فرض از CDN استفاده شده است:
```
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    darkMode: 'class',
    theme: { extend: { colors: { primary: '#0ea5a6' } } }
  }
</script>
```

اگر Build مبتنی‌بر ابزار می‌خواهید (پیشنهادی برای Production):
- نصب ابزارها (Vite/PostCSS/Tailwind)
- ساخت فایل `tailwind.config.js` و `postcss.config.js`
- استخراج کلاس‌ها از Viewها و خروجی CSS تولیدی
- جایگزینی CDN با فایل CSS کامپایل‌شده

---

## نقشه راه (Roadmap)

- دسته‌بندی، ویژگی و تنوع محصول
- قوانین حمل‌ونقل/مالیات پیشرفته و Zones
- کوپن‌های پیشرفته (حداقل خرید، محدودیت دسته/محصول)
- ایمیل سفارش با SMTP
- API REST با JWT
- تم‌ها و چندزبانه
- Docker Compose (Nginx + PHP-FPM + MySQL)
- ابزارهای SAST (PHPStan/Psalm) و CI

---

## مشارکت

پذیرای PR و Issue هستیم:
- شاخه feature از `main` بگیرید، Commitهای اتمیک داشته باشید.
- امنیت را در اولویت قرار دهید.
- اسرار را در مخزن قرار ندهید (از `.env.example` استفاده کنید).

---

## مجوز

این پروژه تحت مجوز GNU GENERAL PUBLIC LICENSE منتشر می‌شود. برای استفاده‌ی تجاری و شخصی آزادید؛ لطفاً کپی‌رایت را حفظ کنید.
```
GNU GENERAL PUBLIC LICENSE 

Copyright (c) 2025 DIMA SOFTWARE GROUP

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```
```
