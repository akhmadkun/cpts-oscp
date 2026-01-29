
# Application Discovery & Enumeration

## Nmap

```bash
$ nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```

Two phenomenal tools that every tester should have in their arsenal are [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) and [Aquatone](https://github.com/michenriksen/aquatone). Both of these tools can be fed raw Nmap XML scan output (Aquatone can also take Masscan XML; EyeWitness can take Nessus XML output) and be used to quickly inspect all hosts running web applications and take screenshots of each.

