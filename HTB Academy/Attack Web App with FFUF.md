# Directory Fuzzing

```bash
ffuf -w <SNIP> -u http://SERVER_IP:PORT/FUZZ

ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

# Extensions Fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ <SNIP>

ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```

# Page Fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

```bash
ffuf -u http://83.136.254.55:49985/blog/FUZZ -w ~/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -ic -c -e .php
```

# Recursive Directory Fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

# Sub-domain Fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```

`Example`

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/

________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.academy.htb/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

:: Progress: [4997/4997] :: Job [1/1] :: 131 req/sec :: Duration: [0:00:38] :: Errors: 4997 ::
```


We see that we do not get any hits back. Does this mean that there are no sub-domain under `academy.htb`? - No.

This means that there are no `public` sub-domains under `academy.htb`, as it does not have a public DNS record, as previously mentioned. Even though we did add `academy.htb` to our `/etc/hosts` file, we only added the main domain, so when `ffuf` is looking for other sub-domains, it will not find them in `/etc/hosts`, and will ask the public DNS, which obviously will not have them.
# Vhost Fuzzing

```bash
ffuf -u 'http://94.237.57.211:35458' -H 'Host: FUZZ.inlanefreight.htb' -w ~/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ic -c -fs 120
```
## Vhosts vs Sub-Domains

The key difference between VHosts and sub-domains is that a VHost is basically a 'sub-domain' served on the same server and has the same IP, such that a single IP could be serving two or more different websites.

`VHosts may or may not have public DNS records.`

In many cases, many websites would actually have sub-domains that are not public and will not publish them in public DNS records, and hence if we visit them in a browser, we would fail to connect, as the public DNS would not know their IP. Once again, if we use the `sub-domain fuzzing`, we would only be able to identify public sub-domains but will not identify any sub-domains that are not public.

This is where we utilize `VHosts Fuzzing` on an IP we already have. We will run a scan and test for scans on the same IP, and then we will be able to identify both public and non-public sub-domains and VHosts.

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'

________________________________________________

 :: Method           : GET
 :: URL              : http://academy.htb:PORT/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

mail2                   [Status: 200, Size: 900, Words: 423, Lines: 56]
dns2                    [Status: 200, Size: 900, Words: 423, Lines: 56]
ns3                     [Status: 200, Size: 900, Words: 423, Lines: 56]
dns1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
lists                   [Status: 200, Size: 900, Words: 423, Lines: 56]
webmail                 [Status: 200, Size: 900, Words: 423, Lines: 56]
static                  [Status: 200, Size: 900, Words: 423, Lines: 56]
web                     [Status: 200, Size: 900, Words: 423, Lines: 56]
www1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
<...SNIP...>
```

We see that all words in the wordlist are returning `200 OK`! This is expected, as we are simply changing the header while visiting `http://academy.htb:PORT/`. So, we know that we will always get `200 OK`. However, if the VHost does exist and we send a correct one in the header, we should get a different response size, as in that case, we would be getting the page from that VHosts, which is likely to show a different page.

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -ic -c -fs 200
```

# Filtering Results

`Ffuf` provides the option to match or filter out a specific HTTP code, response size, or amount of words.

```bash
$ ffuf -h
...SNIP...
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
<...SNIP...>
```

```bash
ffuf -u 'http://83.136.254.55:49985' -H 'Host: FUZZ.academy.htb' -w ~/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ic -c -fs 986
```

# Parameter Fuzzing

## GET Request

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```

```bash
ffuf -u 'http://83.136.254.55:49985/admin/admin.php?FUZZ=key' -H 'Host: admin.academy.htb' -w ~/seclists/Discovery/Web-Content/burp-parameter-names.txt -ic -c -v -fs 798

 :: Method           : GET
 :: URL              : http://83.136.254.55:49985/admin/admin.php?FUZZ=key
 :: Wordlist         : FUZZ: /home/akhmadm/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Host: admin.academy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 798
________________________________________________

[Status: 200, Size: 783, Words: 221, Lines: 54, Duration: 173ms]
| URL | http://83.136.254.55:49985/admin/admin.php?user=key
    * FUZZ: user
```

## POST Request

The main difference between `POST` requests and `GET` requests is that `POST` requests are not passed with the URL and cannot simply be appended after a `?` symbol. `POST` requests are passed in the `data` field within the HTTP request. Check out the [Web Requests](https://academy.hackthebox.com/module/details/35) module to learn more about HTTP requests.

To fuzz the `data` field with `ffuf`, we can use the `-d` flag, as we saw previously in the output of `ffuf -h`. We also have to add `-X POST` to send `POST` requests.

In PHP, "POST" data "content-type" can only accept `application/x-www-form-urlencoded`. So, we can set that in "ffuf" with `-H 'Content-Type: application/x-www-form-urlencoded'`.

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

```bash
ffuf -u 'http://admin.academy.htb:49985/admin/admin.php' -X POST -d 'FUZZ=value' -H 'Content-type: application/x-www-form-urlencoded' -w ~/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 798

 :: Method           : POST
 :: URL              : http://admin.academy.htb:49985/admin/admin.php
 :: Wordlist         : FUZZ: /home/akhmadm/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=value
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 798
________________________________________________

id                      [Status: 200, Size: 768, Words: 219, Lines: 54, Duration: 180ms]
```

# Value Fuzzing

```bash
> ffuf -u 'http://admin.academy.htb:49985/admin/admin.php' -X POST -d 'id=FUZZ' -H 'Content-type: application/x-www-form-urlencoded' -w ./ids.txt -fs 768

 :: Method           : POST
 :: URL              : http://admin.academy.htb:49985/admin/admin.php
 :: Wordlist         : FUZZ: /tmp/tmp.mWDHRnjNqq/ids.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : id=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 768
________________________________________________

73                      [Status: 200, Size: 787, Words: 218, Lines: 54, Duration: 168ms]
```

