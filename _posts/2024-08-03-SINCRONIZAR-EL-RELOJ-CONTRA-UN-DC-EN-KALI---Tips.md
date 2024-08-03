---
title: "Sincronizar el reloj contra un DC en Kali"
date: Sat Aug 03 2024 02:00:00 GMT+0200 (Central European Summer Time)
categories: [Tips, Kali]
tags: [ntp, ntpdate, ntpsec, dc, kerberos]
image: /assets/img/cabeceras/NTP.jpg
---

#### SINCRONIZACIÓN DE NUESTRO RELOJ CONTRA UN DC EN KALI

##### Introducción:

Inauguramos nueva sección de tips o píldoras informáticas. En este caso os mostraré cómo poder sincronizar vuestro Kali contra un controlador de dominio para que los ataques contra Kerberos os funcionen correctamente.

En Kali se hace de una forma distinta ya que el servicio que tenemos que arrancar/configurar se llama de una forma diferente a otras distros basadas en Debian.

##### Procedimiento:
Normalmente usamos el siguiente comando para sincronizar nuestro reloj contra el dominio del servidor DC:

```shell
$ sudo ntpdate -u contoso.com
```

En Kali el servicio _ntp_ o _ntpd_ no funcionan, en su lugar está el servicio _ntpsec_. Y deberemos iniciarlo antes con el siguiente comando:

```shell
$ sudo systemctl start ntpsec
```

Se recomienda cambiar los servidores NTP del archivo "_/etc/ntpsec/ntp.conf_" por estos (comentar los servidores Debian y añadir estos justo debajo):

```
pool ntp.api.bz iburst  # Shanghai server
pool asia.pool.ntp.org iburst # Taiwang server
pool time.nist.gov iburst # Can't to connect in China Because GFW of China
pool time.windows.com iburst # Can't to connect in China Because GFW of China
```

Reiniciar el servicio y ejecutar el comando _ntpdate_:

```bash
$ sudo systemctl restart ntpsec
...
$ sudo ntpdate -u contoso.com
```

Ahora debería sincronizar correctamente.

