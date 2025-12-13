# 📋 Progreso de Mejoras en Posts de Apuntes

**Última actualización**: 2025-12-13
**Objetivo**: Mejorar todos los posts de "Apuntes" con contenido educativo exhaustivo que explique el WHY, HOW y referencias.

---

## ✅ POSTS COMPLETADOS

### 1. Windows Pentesting (2025-12-08)
**Archivo**: `_posts/2025-12-08-WINDOWS-PENTESTING---Apuntes.md`
**Tamaño actual**: ~3,200 líneas
**Estado**: ✅ COMPLETADO

**Secciones añadidas**:
- ✅ **Kerbrute** (~300 líneas)
  - ¿Por qué usar Kerbrute? Ventajas/desventajas
  - 4 modos de operación (userenum, passwordspray, bruteuser, bruteforce)
  - Workflows completos con ejemplos
  - Técnicas de evasión y troubleshooting
  - Links: GitHub, HackTricks

- ✅ **NetExec** (~600 líneas)
  - Sucesor de CrackMapExec
  - 9 protocolos soportados (SMB, LDAP, WinRM, MSSQL, RDP, SSH, FTP, VNC, RDP)
  - Módulos y funcionalidades avanzadas
  - Comparación con herramientas similares
  - Workflows de enumeración y explotación
  - Links: GitHub oficial, documentación wiki

- ✅ **Impacket** (~750 líneas)
  - Suite completa categorizada por funcionalidad
  - 20+ herramientas explicadas (psexec, wmiexec, secretsdump, GetNPUsers, etc)
  - Comparación entre métodos de ejecución remota (tabla)
  - Cómo funciona cada herramienta internamente
  - Ejemplos de uso en AD pentesting
  - Links: GitHub, documentación

- ✅ **WinPEAS** (~385 líneas)
  - Instalación: 4 métodos diferentes
  - Versiones disponibles (x64, x86, .bat, .ps1, ofuscado)
  - Parámetros y opciones completos
  - Interpretación de colores (rojo/amarillo/verde/azul)
  - Workflow recomendado paso a paso
  - 3 ejemplos de output con explotación
  - Comparación: WinPEAS vs manual (ahorra 95% tiempo)
  - Tips: AMSI bypass, background execution, filtrado
  - Links: GitHub PEASS-ng, releases, HackTricks

**Commits**:
- `01a50b5` - Kerbrute, NetExec, Impacket (+1,674 líneas)
- `2d9ac69` - WinPEAS (+385 líneas)

---

### 2. Linux Pentesting (2025-12-07)
**Archivo**: `_posts/2025-12-07-LINUX-PENTESTING---Apuntes.md`
**Tamaño actual**: ~2,400 líneas
**Estado**: ✅ COMPLETADO

**Secciones añadidas**:
- ✅ **LinPEAS** (~400 líneas)
  - ¿Qué es LinPEAS y por qué usarlo?
  - Instalación y transferencia de archivos
  - Interpretación de colores con tabla de criticidad
  - Workflow recomendado para analizar output
  - Opciones y parámetros
  - Limitaciones y consideraciones
  - Links: GitHub PEASS-ng

- ✅ **pspy** (~300 líneas)
  - ¿Cómo funciona sin root? (magia de /proc)
  - Diferencia con `ps aux`
  - Instalación y uso
  - Casos de uso reales (cron jobs, scripts automatizados)
  - Ejemplos de escalación con pspy
  - Workflow completo
  - Links: GitHub pspy

- ✅ **GTFOBins** (~200 líneas)
  - ¿Qué es GTFOBins? (GTFO = Get The Fuck Out)
  - Categorías: Shell, File upload/download/read/write, Library load, SUID, Sudo, Capabilities
  - Cómo usar GTFOBins con ejemplos prácticos
  - Casos de uso con SUID binaries
  - Casos de uso con sudo
  - Casos de uso con capabilities
  - Links: gtfobins.github.io

- ✅ **NFS Exploitation** (~200 líneas)
  - ¿Qué es NFS y por qué es peligroso?
  - Concepto de no_root_squash
  - Enumeración de NFS shares
  - Método 1: Copiar /bin/bash con SUID
  - Método 2: Crear usuario con mismo UID
  - Método 3: Payload con SUID
  - Método 4: SSH keys
  - Defensa contra NFS exploitation

- ✅ **Docker Escape** (~250 líneas)
  - Técnica 1: Socket de Docker montado
  - Técnica 2: Privileged containers
  - Técnica 3: CAP_SYS_ADMIN capability
  - Técnica 4: Kernel exploits desde container
  - Técnica 5: Docker in Docker (DinD)
  - Técnica 6: Misconfigured seccomp/AppArmor
  - Técnica 7: Host PID namespace
  - Herramientas: deepce, CDK (Container Duck Toolkit)
  - Checklist de detección
  - Links: GitHub deepce, CDK

- ✅ **Kernel Exploits** (~300 líneas)
  - ¿Cuándo usar kernel exploits? (último recurso)
  - Advertencias y precauciones
  - Exploit 1: Dirty COW (CVE-2016-5195)
  - Exploit 2: PwnKit (CVE-2021-4034)
  - Exploit 3: DirtyPipe (CVE-2022-0847)
  - Exploit 4: Baron Samedit (CVE-2021-3156)
  - Compilación de exploits
  - Transferencia de exploits
  - Post-explotación
  - Links: GitHub exploits, exploit-db

- ✅ **PATH Hijacking** (~200 líneas)
  - ¿Qué es PATH? Cómo funciona
  - Vulnerabilidad: Scripts sin rutas absolutas
  - Técnica 1: PATH hijacking básico
  - Técnica 2: Library hijacking (LD_PRELOAD, LD_LIBRARY_PATH)
  - Técnica 3: Writable PATH directories
  - Técnica 4: Script injection en $PATH
  - Detección de PATH hijacking
  - Defenderse de PATH hijacking

**Commit**:
- `2d9ac69` - 7 secciones de privilege escalation (+1,592 líneas)

---

## 🔄 POSTS PENDIENTES DE MEJORA

### Prioridad Alta (Posts grandes con mucho uso)

#### 3. Herramientas y Utilidades
**Archivo**: `_posts/2025-12-07-HERRAMIENTAS-Y-UTILIDADES---Apuntes.md`
**Tamaño actual**: ~30 KB
**Estado**: ⏸️ PENDIENTE

**Secciones que necesitan mejora**:
- [ ] **Burp Suite**: Explicar módulos (Proxy, Repeater, Intruder, Scanner), workflows
- [ ] **ffuf**: Web fuzzing, parámetros, wordlists, filtros, técnicas avanzadas
- [ ] **Gobuster**: Directory brute-force, DNS, vhost, comparación con ffuf/dirbuster
- [ ] **Metasploit**: Framework completo, módulos, workflows, evasión AV
- [ ] **Nmap**: Scripts NSE, timing, evasión, interpretación de resultados
- [ ] **Wireshark**: Filtros, análisis de tráfico, identificación de protocolos
- [ ] **Hashcat**: Modos de ataque, reglas, optimización GPU
- [ ] **John the Ripper**: Formatos, reglas, wordlists, comparación con Hashcat

#### 4. Bases de Datos y SQL Injection
**Archivo**: `_posts/2025-12-07-BASES-DE-DATOS-Y-SQL-INJECTION---Apuntes.md`
**Tamaño actual**: ~24 KB
**Estado**: ⏸️ PENDIENTE

**Secciones que necesitan mejora**:
- [ ] **Tipos de SQLi**: In-band, Blind, Out-of-band (explicar diferencias)
- [ ] **SQLMap**: Parámetros avanzados, técnicas, evasión WAF, workflows
- [ ] **MySQL**: Enumeración, extracción, lectura de archivos, RCE via UDF
- [ ] **MSSQL**: xp_cmdshell, linked servers, privilege escalation
- [ ] **PostgreSQL**: Large Objects, COPY, RCE techniques
- [ ] **Oracle**: TNS, SID enumeration, PL/SQL injection
- [ ] **NoSQL Injection**: MongoDB, CouchDB, authentication bypass

#### 5. Enumeración de Redes
**Archivo**: `_posts/2025-12-07-ENUMERACION-DE-REDES---Apuntes.md`
**Tamaño actual**: ~23 KB
**Estado**: ⏸️ PENDIENTE

**Secciones que necesitan mejora**:
- [ ] **Nmap avanzado**: NSE scripts, evasión IDS/IPS, custom scripts
- [ ] **Masscan**: Escaneo masivo, comparación con Nmap
- [ ] **SMB Enumeration**: enum4linux-ng, smbclient, smbmap, crackmapexec
- [ ] **LDAP Enumeration**: ldapsearch, windapsearch, BloodHound
- [ ] **SNMP Enumeration**: snmpwalk, snmp-check, MIBs importantes
- [ ] **DNS Enumeration**: Zone transfer, subdomain enumeration, DNS tunneling

### Prioridad Media (Posts medianos)

#### 6. Web Application Pentesting
**Archivo**: `_posts/2025-12-07-WEB-APPLICATION-PENTESTING---Apuntes.md`
**Tamaño actual**: ~17 KB
**Estado**: ⏸️ PENDIENTE

**Secciones que necesitan mejora**:
- [ ] **XSS**: Reflected, Stored, DOM-based, bypass filters, explotación
- [ ] **CSRF**: Cómo funciona, detección, explotación, bypass tokens
- [ ] **SSRF**: Tipos, bypass filters, cloud metadata exploitation
- [ ] **XXE**: External entities, file reading, SSRF via XXE, blind XXE
- [ ] **Deserialization**: Java, PHP, Python, .NET, detección y explotación
- [ ] **File Upload**: Bypass extensions, magic bytes, double extensions

#### 7. Metodología Pentesting
**Archivo**: `_posts/2025-12-07-METODOLOGIA-PENTESTING---Apuntes.md`
**Tamaño actual**: ~16 KB
**Estado**: ⏸️ PENDIENTE

**Secciones que necesitan mejora**:
- [ ] **Reconnaissance**: OSINT, passive vs active, herramientas
- [ ] **Enumeration**: Protocolos comunes, workflows por servicio
- [ ] **Exploitation**: Búsqueda de exploits, adaptación, evasión AV
- [ ] **Post-Exploitation**: Persistence, pivoting, lateral movement
- [ ] **Reporting**: Estructura, severidad, reproducción, remediación

#### 8. Reverse Shells Cheatsheet
**Archivo**: `_posts/2025-12-12-REVERSE-SHELLS---Cheatsheet.md`
**Tamaño actual**: ~16 KB
**Estado**: ⏸️ PENDIENTE

**Secciones que necesitan mejora**:
- [ ] **Listeners**: netcat, pwncat, socat, metasploit, diferencias
- [ ] **Bash**: Diferentes técnicas, /dev/tcp, named pipes
- [ ] **Python**: socket, pty, subprocess, upgrading shells
- [ ] **PHP**: exec, shell_exec, system, passthru, backticks
- [ ] **PowerShell**: TCP, UDP, obfuscation, AMSI bypass
- [ ] **Upgrading shells**: TTY, stty, rlwrap, socat

#### 9. Post-Explotación y Lateral Movement
**Archivo**: `_posts/2025-12-07-POST-EXPLOTACION-Y-LATERAL-MOVEMENT---Apuntes.md`
**Tamaño actual**: ~13 KB
**Estado**: ⏸️ PENDIENTE

**Secciones que necesitan mejora**:
- [ ] **Persistence**: Linux (cron, systemd, bashrc), Windows (registry, services, tasks)
- [ ] **Credential Harvesting**: Memory dumps, SAM/NTDS, browser passwords
- [ ] **Pivoting**: SSH tunneling, chisel, ligolo-ng, proxychains
- [ ] **Lateral Movement**: Pass-the-Hash, Pass-the-Ticket, RDP, WinRM
- [ ] **Data Exfiltration**: DNS, ICMP, HTTP, encrypted channels

---

## 📊 ESTADÍSTICAS

### Trabajo Completado
- **Posts completados**: 2/9 (22%)
- **Líneas añadidas**: 3,637 líneas
  - Windows: 2,045 líneas
  - Linux: 1,592 líneas
- **Commits realizados**: 3
  - `01a50b5` - Windows (Kerbrute, NetExec, Impacket)
  - `2d9ac69` - Windows (WinPEAS) + Linux (7 secciones)

### Trabajo Pendiente
- **Posts pendientes**: 7/9 (78%)
- **Estimación de líneas a añadir**: ~8,000-10,000 líneas
- **Tiempo estimado**: 10-15 horas de trabajo

---

## 🎯 CRITERIOS DE CALIDAD

Cada sección debe incluir:

### ✅ Obligatorio
- **WHY**: ¿Por qué usar esta herramienta? Ventajas/desventajas
- **HOW**: ¿Cómo funciona internamente? Conceptos clave
- **Instalación**: Múltiples métodos si aplica
- **Parámetros**: Opciones principales y casos de uso
- **Ejemplos prácticos**: Workflows del mundo real
- **Links**: Repositorio oficial, documentación, referencias

### ⭐ Deseable
- Comparación con alternativas (tabla comparativa)
- Troubleshooting (errores comunes y soluciones)
- Tips y trucos avanzados
- Evasión (AV, IDS/IPS, WAF) si aplica
- Limitaciones y consideraciones

### ❌ Evitar
- Chorro de comandos sin contexto
- Teoría abstracta sin ejemplos
- Comandos sin explicar qué hacen
- Falta de referencias o links

---

## 🚀 PRÓXIMOS PASOS

### Sesión 1 (Prioridad Alta)
1. **Herramientas y Utilidades** - Burp Suite, ffuf, Gobuster, Metasploit, Nmap
2. **Bases de Datos y SQL Injection** - SQLMap, MySQL, MSSQL, NoSQL

### Sesión 2 (Prioridad Alta)
3. **Enumeración de Redes** - Nmap NSE, SMB, LDAP, SNMP, DNS

### Sesión 3 (Prioridad Media)
4. **Web Application Pentesting** - XSS, CSRF, SSRF, XXE, Deserialization
5. **Reverse Shells** - Listeners, bash, python, php, powershell, upgrading

### Sesión 4 (Prioridad Media)
6. **Metodología Pentesting** - Reconnaissance, Enumeration, Exploitation
7. **Post-Explotación** - Persistence, Pivoting, Lateral Movement, Exfiltration

---

## 📝 NOTAS IMPORTANTES

### Configuración Git
- **User**: 4ndymcfly
- **Email**: info@hackingepico.com
- Configurado globalmente con `git config --global`

### Infraestructura
- **Hosting**: GitHub Pages (migrado desde Netlify)
- **DNS**: Cloudflare en modo "DNS only" (no proxied)
  - Motivo: ISP Movistar bloquea IPs de Cloudflare por anti-piratería LaLiga
- **Dominio**: hackingepico.com
- **Build**: Jekyll con GitHub Actions

### Commits
- Usar formato exhaustivo en mensaje de commit
- Incluir resumen de cambios por post
- Finalizar con firma Claude Code
- Ejemplo:
  ```
  Add: Comprehensive [tema] guide to [post]

  [POST] IMPROVEMENTS (+XXX lines):
  - Sección 1: Descripción
  - Sección 2: Descripción

  All sections include:
  - WHY, HOW, links, examples, workflows

  🤖 Generated with [Claude Code](https://claude.com/claude-code)
  Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
  ```

---

## 🔗 ENLACES ÚTILES

### Repositorios Principales
- **PEASS-ng** (WinPEAS/LinPEAS): https://github.com/peass-ng/PEASS-ng
- **Impacket**: https://github.com/fortra/impacket
- **NetExec**: https://github.com/Pennyw0rth/NetExec
- **GTFOBins**: https://gtfobins.github.io/
- **HackTricks**: https://book.hacktricks.xyz/

### Documentación
- **NetExec Wiki**: https://www.netexec.wiki/
- **Impacket Examples**: https://github.com/fortra/impacket/tree/master/examples
- **PEASS-ng Releases**: https://github.com/peass-ng/PEASS-ng/releases

---

**Fin del documento de progreso**
**Última actualización**: 2025-12-13 21:20 UTC
