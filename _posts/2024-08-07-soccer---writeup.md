---
redirect_from:
  - /posts/SOCCER-WriteUp/

title: "Soccer - WriteUp"
date: Wed Aug 07 2024 10:45:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, dirb, reverse-shell, sudo, nginx, php, linux, ssh]
image: /assets/img/htb-writeups/Pasted-image-20240123120955.png
---

{% include machine-info.html
  machine="Soccer"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Soccer](/assets/img/htb-writeups/Pasted-image-20240123120955.png)

-------

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123120955.png)

-------

NMAP
```bash
sudo nmap -sCV -p22,80,9091 10.129.6.32 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-23 12:12 CET
Stats: 0:00:13 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 12:12 (0:00:06 remaining)
Nmap scan report for 10.129.6.32
Host is up (0.043s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Tue, 23 Jan 2024 11:12:51 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Tue, 23 Jan 2024 11:12:51 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|     </html>
|   RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Tue, 23 Jan 2024 11:12:52 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

soccer.htb > /etc/hosts

HTTP

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123121549.png)

FUZZING

```bash
$ feroxbuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://soccer.htb
```

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123122254.png)

Si vamos a http://soccer.htb/tiny/ vemos un panel de login:

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123122349.png)

Examinamos el código fuente de la página y damos con la versión.

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123123804.png)

Probamos las credenciales por defecto _admin:admin@123_ y entramos.

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123124049.png)

Confirmamos versión encontrada y continuamos.

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123124530.png)

Tenemos acceso de escritura en la carpeta /uploads, vamos a preparar una reverse shell y la subimos.

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123125125.png)

Nos ponemos en escucha y navegamos a la url:

```http
http://soccer.htb/tiny/uploads/fullshell.php
```

Y accedemos a la máquina. Hay que darse un poco de prisa porque por detrás se ejecuta una tarea que borra todos los archivos subidos.

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123125400.png)

Sanitizamos consola y continuamos...

Si vamos a los archivos de configuración de _nginx_ vemos que tiene un subdominio nuevo:

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123131947.png)

Lo damos de alta en el /etc/hosts e introducimos la URL en el navegador.

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123133231.png)

Si nos fijamos ahora tiene más opciones.

Nos registramos en la página y entramos para ver qué vemos.

![SOCCER](/assets/img/htb-writeups/Pasted-image-20240123133818.png)

Vamos a ver qué hace por detrás capturando las peticiones con BurpSuite:

```http
player:PlayerOftheMatch2022
```
---

**Última actualización**: 2024-08-07<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
