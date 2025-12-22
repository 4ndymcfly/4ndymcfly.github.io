---
title: Drive - WriteUp
date: 'Sat, 16 Aug 2025 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Linux
tags:
  - ctf
  - nmap
  - htb
  - hashcat
  - linpeas
  - nginx
  - ffuf
  - linux
  - mysql
  - php
image: /assets/img/cabeceras/2025-08-16-DRIVE-WRITEUP.png
description: >-
  Drive es una máquina Linux con un servicio de intercambio de archivos
  susceptible a la Referencia Directa a Objetos Insegura (IDOR), mediante la
  cual se obtiene una contraseña en texto plano, lo que permite el acceso SSH al
  equipo. Se descubren copias de seguridad cifradas de la base de datos, que se
  desbloquean mediante una contraseña codificada expuesta en un repositorio de
  Gitea. Se descifran los hashes de las copias de seguridad, lo que permite el
  acceso a otro usuario del sistema que tiene acceso a un binario propiedad del
  usuario root con el bit SUID activado. Se aplica ingeniería inversa al
  programa, lo que revela el uso indebido de una función printf, que se utiliza
  para leer y posteriormente omitir el canario en la pila. Finalmente, se
  utiliza una secuencia de dispositivos ROP para obtener un shell en el
  objetivo.
---

{% include machine-info.html
  machine="Drive"
  os="Linux"
  difficulty="Hard"
  platform="HTB"
%}


## Enumeración

NMAP

```bash
$ nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.183.136

Nmap scan report for drive.htb (10.129.183.136)
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 27:5a:9f:db:91:c3:16:e5:7d:a6:0d:6d:cb:6b:bd:4a (RSA)
|   256 9d:07:6b:c8:47:28:0d:f2:9f:81:f2:b8:c3:a6:78:53 (ECDSA)
|_  256 1d:30:34:9f:79:73:69:bd:f6:67:f3:34:3c:1f:f9:4e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Doodle Grive
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```http
whatweb http://10.129.183.136
http://10.129.183.136 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.183.136], RedirectLocation[http://drive.htb/], Title[301 Moved Permanently], nginx[1.18.0]
http://drive.htb/ [200 OK] Bootstrap, Cookies[csrftoken], Country[RESERVED][ZZ], Django, Email[customer-support@drive.htb,support@drive.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.183.136], JQuery[3.0.0], Script, Title[Doodle Grive], UncommonHeaders[x-content-type-options,referrer-policy,cross-origin-opener-policy], X-Frame-Options[DENY], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

HTTP

![DRIVE](/assets/img/htb-writeups/Pasted-image-20240119120640.png)

Posibles usuarios:

![DRIVE](/assets/img/htb-writeups/Pasted-image-20240119120717.png)

Panel de registro y login: 

![DRIVE](/assets/img/htb-writeups/Pasted-image-20240119120827.png)

![DRIVE](/assets/img/htb-writeups/Pasted-image-20240119120850.png)

Procedemos a registrarnos y hacer login.

Al entrar en nuestra cuenta tenemos dos opciones nuevas:

![DRIVE](/assets/img/htb-writeups/Pasted-image-20240119122812.png)

```http
martin:Xk4@KjyrYv8t194L!
```

```bash
$ ssh martin@10.129.183.136 -L 3000:127.0.0.1:3000
```

```http
http://localhost:3000/
martinCruz:Xk4@KjyrYv8t194L!
```

```http
tom:johnmayer7
```

### WRITEUP COMPLETO:

https://medium.com/@zharsuke/hack-the-box-drive-walkthrough-bd22f1320755

> Pruebas

Para las pruebas iniciales, intento borrar el subdominio, si lo hay en la aplicación web. Pero el resultado es nada.

```bash
$ ffuf -u http://drive.htb/ -H "Host: FUZZ.drive.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fl 8
```

![image](https://miro.medium.com/v2/resize:fit:700/1*VvU_r3c7rgz89xqtncvvrQ.png)

Subdominio difuso

Luego intento borrar el directorio y encontrar el punto final que me interese y que sea suscribirme.

```bash
$ ffuf -u http://drive.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt - fc 302
```

![image](https://miro.medium.com/v2/resize:fit:700/1*Fibm79AQVymXVcVUfRJqRA.png)

Entonces, intento acceder al punto final /suscribir pero no puedo, aparece el mensaje de error 500 del servidor. Pero cuando cambio el método de GET a POST, el resultado es 403 Prohibido. Hmm, es como una pantalla de Django. Además, no sé qué tipo de carga útil debería insertarse. Entonces el resultado es el mismo cuando intento probar el punto final /password_reset.

![image](https://miro.medium.com/v2/resize:fit:700/1*ShE_3gmluULOrO6Mqi38RA.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*8Lzi3a5k7r2sibg5Q4xtLw.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*H5UocHHaRijSKH6e9JH2kg.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*y2lSiaOvy3HjzC56Qjubgg.png)

Deberíamos encontrar los próximos posibles vectores de ataque.

Luego intento gospider para encontrar el archivo de ruta recursiva. Hay custom.js que me interesa, pero cuando accedo a él, parece que no hay nada allí.

```bash
$ gospider -s "http://drive.htb/"
```

![image](https://miro.medium.com/v2/resize:fit:700/1*TYObHoJZLiDBmtFALrpNig.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*PXbBZHPlT9JcRaiA2J95QQ.png)

Hmm, está bien si no he encontrado ninguna pista. Lo siguiente es intentar interceptar cada solicitud.

Cuando intercepto una solicitud de registro, hay una cookie que es csrftoken y luego csrfmiddlewaretoken en el parámetro. El siguiente es normalmente el parámetro que ingresamos desde el registro del formulario. Según [**_la documentación de Django_**](https://docs.djangoproject.com/en/4.2/ref/csrf/) , CsrfViewMiddleware envía esta cookie con la respuesta cada vez que se llama a django.middleware.csrf.get_token(). También puede enviarlo en otros casos. Por razones de seguridad, el valor del secreto cambia cada vez que un usuario inicia sesión. Un campo de formulario oculto con el nombre 'csrfmiddlewaretoken', presente en todos los formularios POST salientes.

![image](https://miro.medium.com/v2/resize:fit:700/1*EJwTt00UOo_hijL3PmWqUA.png)

Después de iniciar sesión, los usuarios tendrán otra cookie que es sessionid.

![image](https://miro.medium.com/v2/resize:fit:700/1*mN5PMAumcN4f89PFd_Qygw.png)

Luego, intento cargar un archivo que contenga un script que me lleve al shell inverso. Intento configurar el oyente y luego acceder a los detalles del archivo, pero el resultado no es nada. Parece que solo podemos leer los archivos, no podemos escribirlos ni ejecutarlos.

![image](https://miro.medium.com/v2/resize:fit:700/1*8zAwnXttJkyOhxjnAkbhCw.png)

>Interceptar al cargar el archivo

![image](https://miro.medium.com/v2/resize:fit:429/1*j0v3ujEYvwVCzwYrCEEvWg.png)

>Establecer oyente

![image](https://miro.medium.com/v2/resize:fit:700/1*MZKLuS2dcUxwuSfPgDusEQ.png)

>Archivo de detalle

Pero, del experimento anterior, lo que me interesa es que cuando accedemos al archivo de detalles, se dirige a /123/getFileDetail/. Significa el número de llamada de la aplicación web como archivo identificador para obtener el archivo. Mmm. Luego intento invadir la solicitud con la carga útil del número de marca. Luego configure las cargas útiles en números de secuencia del 1 al 1000 y esperemos que podamos encontrar el archivo no autorizado.

![image](https://miro.medium.com/v2/resize:fit:700/1*eWQJ1_bWX24b676KV6IwDg.png)

>Marcar el número de identificación como carga útil

![image](https://miro.medium.com/v2/resize:fit:700/1*uk3ySFs-6p30QlVurwg0cA.png)

>Establecer la carga útil del número de secuencias

El resultado es que hay varias identificaciones que tienen el código de estado 200. Después de verificarlas una por una, no hay ninguna que me interese. Pero hay una identificación que tiene el código de estado 401 no autorizado al que no podemos acceder. Hmm, parece que deberíamos encontrar una manera de leer archivos no autorizados.

![image](https://miro.medium.com/v2/resize:fit:700/1*i29sLsqkThm4XS7-B1cfww.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*QzPG4e-B7R--NjIZu5Izbg.png)

## Explotación

### Shell como Martin

En la página del archivo de lista, hay una reserva que dirige al punto final /123/block/, que es el nuevo punto final que nunca se prueba.

![image](https://miro.medium.com/v2/resize:fit:700/1*TbUKyKlfyi9RyJ37T2PiOw.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*75LDmSfr10vBveo1Z_QfEQ.png)

Luego, intento bloquear el punto final del intruso nuevamente y espero que pueda acceder al archivo no autorizado. Después, el resultado es que hay varios códigos de estado 200, más que antes.

![image](https://miro.medium.com/v2/resize:fit:700/1*KQWirLHOusy6RW8Wzr-ZJQ.png)

Luego, trato de verificarlos uno por uno y encuentro la credencial ssh de Martin y encontré el directorio de respaldo de la base de datos. ¡¡Finalmente!!

![image](https://miro.medium.com/v2/resize:fit:700/1*HwnjDF_f0aBD4HtGTPfWqA.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*5SlHQcrk7rAtirrcjFhatw.png)

> IDOR

Esta vulnerabilidad es IDOR, que significa Insecure Direct Object. Según [**_PortSwigger_**](https://portswigger.net/web-security/access-control/idor) , IDOR es un tipo de vulnerabilidad [de control de acceso](https://portswigger.net/web-security/access-control) que surge cuando una aplicación utiliza información proporcionada por el usuario para acceder a objetos directamente.

Luego intento iniciar sesión en ssh como martin, ¡y luego funciona! Pero no hay ningún indicador de usuario en el directorio martin. Luego trato de ver la lista de usuarios en el directorio /home, el resultado es que hay cuatro usuarios: martin, cris, git y tom. huftt..

![image](https://miro.medium.com/v2/resize:fit:650/1*91Uq8RPTGmqCvFp6TwF7GQ.png)

### Shell como Tom

A continuación, intento descargar el archivo de copia de seguridad de la base de datos local para que podamos analizarlo. Así que creo un servidor Python en forma remota y luego intento iniciar sesión en local.

![image](https://miro.medium.com/v2/resize:fit:700/1*w54S9hqVd2QjI4tTlpU3wA.png)

Listar archivos en el directorio de copias de seguridad

martin@drive:/var/www/backups$ python3 -m http.servidor

![image](https://miro.medium.com/v2/resize:fit:700/1*pxXx6zOIpWENRrJ2GtBdnQ.png)

Configurar el servidor Python en remoto

wget http://10.10.11.235:8000/1_Sep_db_backup.sqlite3.7z

![image](https://miro.medium.com/v2/resize:fit:700/1*CnBNSeGWIm3vpcJkbkyFCQ.png)

Descargar archivo con wget

Hay un total de 5 archivos que descargué con cuatro archivos zip y un archivo sqlite db.

![image](https://miro.medium.com/v2/resize:fit:687/1*GFPSphF3l7q2BLQOBVsJdA.png)

Luego intento acceder al archivo db con el navegador sqlite db y encontré la tabla de usuarios.

![image](https://miro.medium.com/v2/resize:fit:700/1*cyfEWCpfbse2KWfYz7WgxA.png)

Intento almacenar la contraseña hash en un solo archivo.

![image](https://miro.medium.com/v2/resize:fit:700/1*cBR-NDHSgEwkVpuepPShiw.png)

La idea es descifrar la contraseña hash con hashcat o john, pero parece que los hash contienen sal, no solo sha1. Así que intenté buscar [**_un ejemplo de hashcat en modo hash_**](https://hashcat.net/wiki/doku.php?id=example_hashes) y lo encontré.

![image](https://miro.medium.com/v2/resize:fit:700/1*bUpJoJs5hB1Ph7P6WiPohA.png)

Luego intento descifrar las contraseñas con hashcat pero parece imposible de descifrar.

![image](https://miro.medium.com/v2/resize:fit:700/1*_f2wTPx7Bb6yhevX7DM80w.png)

Después de eso, intento extraer archivos zip, pero debería insertar la contraseña. Intento con la contraseña martin que encontramos anteriormente, pero no funciona.

![image](https://miro.medium.com/v2/resize:fit:478/1*gejulNpma9vov1QAapXTWA.png)

![image](https://miro.medium.com/v2/resize:fit:478/1*1f50EMoeWin-Ae-GEAgN_Q.png)

Hmm, parece que debemos encontrar la contraseña zip de otra manera. Entonces intento ejecutar linpeas para analizarlo.

![image](https://miro.medium.com/v2/resize:fit:700/1*lxI6-AwwBXxf7acPy0mffg.png)

Después de mirar a mi alrededor, me doy cuenta de que con el escaneo de puertos anterior hay el puerto 3000. Así que busco puertos activos y hay varios puertos activos que son 33060, que es el puerto mysql, 3306 también mysql, 80 http, 53 dns, 22 ssh, y 3000.

![image](https://miro.medium.com/v2/resize:fit:700/1*91V58Cjnuhl0TSDi-kwSkA.png)

## Escalada

Entonces, intento reenviar localmente los puertos activos a mi máquina local para poder acceder a ellos. Intento redireccionar el puerto local 3000 y luego acceder a él, ¡hay una página de gitea!

ssh -L 3000:127.0.0.1:3000 martin@drive.htb

![image](https://miro.medium.com/v2/resize:fit:700/1*5pUwTULBSfkm3ipHKLlxYg.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*iZBaetj37BcRUSBkUpb7ig.png)

Luego intento iniciar sesión con la credencial de Martin (use el correo electrónico en la base de datos antes, la contraseña en el punto final del bloque), hay un repositorio DoodleGrive.

![image](https://miro.medium.com/v2/resize:fit:700/1*1r1xYAfcw2XFmx6pC2Ch-A.png)

Revisé db_backup.sh y encontré la contraseña zip.

![image](https://miro.medium.com/v2/resize:fit:700/1*fEgnKobJ7Ih-pH7I0Cy3BA.png)

Luego intento extraer la contraseña y funciona y la administro. Después de verificarlo uno por uno, hay dos tipos de hash de contraseña: sha1$ y pbkdf2_sha256$.

![image](https://miro.medium.com/v2/resize:fit:700/1*_WrXF6bMIKRvJ0OvFUQPsw.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*oAcvl08ImjcvPhcFh_RLdA.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*SWme0EzrMESOtjqujFqK-w.png)

Después de eso, intenté descifrar hashes nuevamente con hashcat y encontré la contraseña.

hashcat -m 124 hashsha1.txt /usr/share/wordlists/rockyou.txt

![image](https://miro.medium.com/v2/resize:fit:700/1*SvHYVCA4-2bkXqHr4UNjng.png)

Después, intento hacer coincidir el hash con el usuario en el navegador db y el resultado es el tom de la contraseña. Intento iniciar sesión en ssh insertando la contraseña arriba una por una, luego funciona. ¡La contraseña es johnmayer7 y obtuve la bandera de usuario!

![image](https://miro.medium.com/v2/resize:fit:700/1*0GIWSG90upabP9YJZLoP0g.png)

Lea la bandera del usuario:

```bash
tom@drive:~$ gato usuario.txt   
0cb8******************************
```


---

**Última actualización**: 2025-08-16<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
