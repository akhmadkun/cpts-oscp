
https://www.root-me.org/en/Challenges/App-Script/Bash-Restricted-shells?q=%2Fen%2FChallenges%2FApp-Script%2FRestricted-shells

# Go play at root-me for a change !!

Root-Me / PicoCTF / TryHackMe → HTB / Proving Grounds → OSCP/CPTS

# Docker for Web Pentest

## Juice Shop

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

## DVWA

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

## nowasp

```bash
docker run --rm -p 3000:3000 citizenstig/nowasp
```

## Vulhub/Vulhub

```bash
git clone --depth 1 https://github.com/vulhub/vulhub

cd vulhub/langflow/CVE-2025-3248  # Example: enter a vulnerability directory
docker compose up -d
```


## webgoat

```bash
docker run -p 8080:8080 --rm webgoat/webgoat
```

