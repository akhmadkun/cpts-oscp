
# Application Discovery & Enumeration

## Nmap

```bash
$ nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```

Two phenomenal tools that every tester should have in their arsenal are [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) and [Aquatone](https://github.com/michenriksen/aquatone). Both of these tools can be fed raw Nmap XML scan output (Aquatone can also take Masscan XML; EyeWitness can take Nessus XML output) and be used to quickly inspect all hosts running web applications and take screenshots of each.

## EyeWitness

EyeWitness can take the XML output from both Nmap and Nessus and create a report with screenshots of each web application present on the various ports using Selenium.

Clone the [repository](https://github.com/FortyNorthSecurity/EyeWitness), navigate to the `Python/setup` directory and run the `setup.sh` installer script.

Let's run the default `--web` option to take screenshots using the Nmap XML output from the discovery scan as input.

```bash
$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness

################################################################################
#                                  EyeWitness                                  #
################################################################################
#           FortyNorth Security - https://www.fortynorthsecurity.com           #
################################################################################

Starting Web Requests (26 Hosts)
Attempting to screenshot http://app.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local:8000
Attempting to screenshot http://app-dev.inlanefreight.local:8080
Attempting to screenshot http://gitlab-dev.inlanefreight.local
Attempting to screenshot http://10.129.201.50
Attempting to screenshot http://10.129.201.50:8000
..SNIP..
Finished in 57.859838008880615 seconds

[*] Done! Report written in the /home/mrb3n/Projects/inlanfreight/inlanefreight_eyewitness folder!
Would you like to open the report now? [Y/n]
```

## Aquatone

[Aquatone](https://github.com/michenriksen/aquatone), as mentioned before, is similar to EyeWitness and can take screenshots when provided a `.txt` file of hosts or an Nmap `.xml` file with the `-nmap` flag.

```bash
$ wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```

```bash
$ cat web_discovery.xml | ./aquatone -nmap

aquatone v1.7.0 started at 2021-09-07T22:31:03-04:00

Targets    : 65
Threads    : 6
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://web01.inlanefreight.local:8000/: 403 Forbidden
http://app.inlanefreight.local/: 200 OK
http://jenkins.inlanefreight.local/: 403 Forbidden
http://app-dev.inlanefreight.local/: 200 
http://app-dev.inlanefreight.local/: 200 

..SNIP..

Screenshots:
 - Successful : 65
 - Failed     : 0

Wrote HTML report to: aquatone_report.html
```

# WordPress - Discovery & Enum

A quick way to identify a WordPress site is by browsing to the `/robots.txt` file. A typical robots.txt on a WordPress installation may look like:

```http
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```

Here the presence of the `/wp-admin` and `/wp-content` directories would be a dead giveaway that we are dealing with WordPress. Typically attempting to browse to the `wp-admin` directory will redirect us to the `wp-login.php` page.

WordPress stores its plugins in the `wp-content/plugins` directory. This folder is helpful to enumerate vulnerable plugins. Themes are stored in the `wp-content/themes` directory. These files should be carefully enumerated as they may lead to RCE.

## Enumeration

```shell
$ curl -s http://blog.inlanefreight.local | grep WordPress

<meta name="generator" content="WordPress 5.8" /
```

```shell
$ curl -s http://blog.inlanefreight.local/ | grep themes
```

```shell
$ curl -s http://blog.inlanefreight.local/ | grep plugins
```

```shell
 curl -s http://blog.inlanefreight.local/?p=1 | grep plugins
```

## WPScan

The `--enumerate` flag is used to enumerate various components of the WordPress application, such as plugins, themes, and users.

```shell
$ sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>

<SNIP>

[+] URL: http://blog.inlanefreight.local/ [10.129.42.195]
[+] Started: Thu Sep 16 23:11:43 2021

Interesting Finding(s):
```