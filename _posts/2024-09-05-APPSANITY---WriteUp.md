---
title: "Appsanity - WriteUp"
date: Thu Sep 05 2024 11:00:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, winrm, windows, evil-winrm, ffuf, iis, bash]
image: /assets/img/htb-writeups/Pasted-image-20240126104024.png
---

{% include machine-info.html
  machine="Appsanity"
  os="Windows"
  difficulty="Hard"
  platform="HTB"
%}

![Appsanity](/assets/img/htb-writeups/Pasted-image-20240126104024.png)

---

---
----

![APPSANITY](/assets/img/htb-writeups/Pasted-image-20240126104024.png)

----

```bash
$ evil-winrm -i 10.129.5.86 -u 'devdoc' -p '1g0tTh3R3m3dy!!'
$ evil-winrm -i 10.129.5.86 -u 'Administrator' -H '3d636ff292d255b1a899123876635a22'
```

NMAP

```bash
# Nmap 7.94SVN scan initiated Fri Jan 26 10:42:05 2024 as: nmap -sCV -p 80,443,5985,7680 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nma
p-bootstrap.xsl -oN targeted -oX targetedXML 10.129.5.86
Nmap scan report for 10.129.5.86
Host is up (0.082s latency).

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
|_http-server-header: Microsoft-IIS/10.0
443/tcp  open  https?
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp open  pando-pub?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 26 10:42:55 2024 -- 1 IP address (1 host up) scanned in 50.05 seconds
```

Agregamos _meddigi.htb_ al hosts.

HTTP

![APPSANITY](/assets/img/htb-writeups/Pasted-image-20240126104916.png)

```http
https://meddigi.htb/signin
```

![APPSANITY](/assets/img/htb-writeups/Pasted-image-20240126105022.png)

```http
https://meddigi.htb/signup
```

![APPSANITY](/assets/img/htb-writeups/Pasted-image-20240126105121.png)

WHATWEB

```http
$ whatweb https://meddigi.htb
https://meddigi.htb [200 OK] Bootstrap, Cookies[.AspNetCore.Mvc.CookieTempDataProvider], Country[RESERVED][ZZ], Email[support@meddigi.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], HttpOnly[.AspNetCore.Mvc.CookieTempDataProvider], IP[10.129.5.86], JQuery, Microsoft-IIS[10.0], Script, Strict-Transport-Security[max-age=2592000], Title[MedDigi]
```

FUZZING

Subdominios:
```bash
$ ffuf -u https://meddigi.htb/ -H "Host: FUZZ.meddigi.htb" -w /usr/share/seclists/Discovery/DNS/subdomain-megalist.txt
```

![APPSANITY](/assets/img/htb-writeups/Pasted-image-20240126112040.png)

Encuentra el subdominio _portal_ lo agregamos al hosts y vemos qué hay:

![APPSANITY](/assets/img/htb-writeups/Pasted-image-20240126112142.png)

WriteUp Incompleto - No guardé los cambios - Lo siento :)
---

**Última actualización**: 2024-09-05<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
