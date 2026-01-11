---
redirect_from:
  - /posts/SQUASHED-WriteUp/

title: Squashed - WriteUp
date: 'Wed, 12 Jun 2024 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Linux
tags:
  - ctf
  - nmap
  - htb
  - reverse-shell
  - apache
  - php
  - linux
  - ssh
  - bash
  - john
image: /assets/img/cabeceras/2024-06-12-SQUASHED-WRITEUP.png
description: >-
  Squashed es una máquina Linux de dificultad fácil que combina la
  identificación y el aprovechamiento de configuraciones incorrectas en recursos
  compartidos NFS mediante la suplantación de usuarios. Además, incorpora la
  enumeración de una pantalla X11 en la escalada de privilegios, al pedirle al
  atacante que tome una captura de pantalla del escritorio actual.
---

{% include machine-info.html
  machine="Squashed"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}


## Reconocimiento

NMAP

```bash
# Nmap 7.94SVN scan initiated Thu Jan 25 19:46:14 2024 as: nmap -sCV -p 22,80,111,2049,34021,34593,35533,55917 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.228.109
Nmap scan report for 10.129.228.109
Host is up (0.059s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Built Better
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34593/tcp   mountd
|   100005  1,2,3      42071/udp6  mountd
|   100005  1,2,3      50611/tcp6  mountd
|   100005  1,2,3      54040/udp   mountd
|   100021  1,3,4      34391/tcp6  nlockmgr
|   100021  1,3,4      35533/tcp   nlockmgr
|   100021  1,3,4      43179/udp   nlockmgr
|   100021  1,3,4      54471/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs      3-4 (RPC #100003)
34021/tcp open  mountd   1-3 (RPC #100005)
34593/tcp open  mountd   1-3 (RPC #100005)
35533/tcp open  nlockmgr 1-4 (RPC #100021)
55917/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

HTTP

Esta es la web, pero es estática y por ahora no la vamos a tocar:

![SQUASHED](/assets/img/htb-writeups/Pasted-image-20240125195208.png)

Nos vamos a centrar en enumerar el puerto 111 TCP y 2049 TCP - NFS

```bash
$ showmount -e 10.129.228.109

Export list for 10.129.228.109:
var    *
/var/www/html *
```

Vemos dos rutas que se pueden montar. Vamos a ello.

Nos ponemos como root y creamos una carpeta en la ruta /mnt/squashed.

Dentro de ella, creamos las carpetas ross y html y comanzamos:

```bash
$ mount -t nfs -o vers=3 10.129.228.109:/home/ross /mnt/squashed/ross -o nolock
...
$ mount -t nfs -o vers=3 10.129.228.109:/var/www/html /mnt/squashed/html -o nolock
```

Hacemos un _tree_ rápido y solo tenemos acceso a un archivo. Es una base de datos de _keepass_. Nos la copiamos a nuestra carpeta e intentamos acceder a ella.

![SQUASHED](/assets/img/htb-writeups/Pasted-image-20240125201259.png)

Pero no tenemos suerte:

```bash
$ keepass2john Passwords.kdbx
! Passwords.kdbx : File version '40000' is currently not supported!
```

Tenemos que buscar otro camino...

```http
INCOMPLETO - Próximamente...
```


---

**Última actualización**: 2024-06-12<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
