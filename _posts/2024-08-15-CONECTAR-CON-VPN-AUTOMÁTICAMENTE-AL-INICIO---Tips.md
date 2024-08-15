---
title: "Conectar con VPN automaticamente al inicio"
date: Thu Aug 15 2024 11:07:40 GMT+0200 (Central European Summer Time)
categories: [Tips, OpenVPN]
tags: [service, systemctl, kali, openvpn]
image: /assets/img/cabeceras/openvpn-logo.jpg
---

# CÓMO CONECTAR AUTOMÁTICAMENTE TU VPN PREFERIDA AL INICIO DEL SISTEMA

### INTRODUCCIÓN:

A veces, cuando estamos haciendo máquinas CTF en plataformas como HackTheBox, TryHackMe, Proving Grounds, etc... debemos estar conectando a la VPN cada vez que iniciamos nuestra máquina y dejar la conexión en segundo plano o estar pendiente de que accidentalmente la cerremos sin querer.

Este pequeño tip, si no lo conocías, te vendrá perfecto para olvidarte de conectar y poder cerrar la conexión accidentalmente, ya que se inicia como servicio y es bastante estable. También nos vendrá bien sobretodo cuando estamos periodos de tiempo haciendo CTFs en una sola plataforma. Solo tendremos que iniciar nuestra máquina, navegar a la plataforma e iniciar la VM, olvidándonos de todo lo demás.

### PROCEDIMIENTO:

La manera de conseguir esto es muy sencilla, copiamos el archivo `.ovpn` de nuestra plataforma favorita en la ruta:

```bash
/etc/openvpn/client/
```

y lo renombramos a:

```bash
openvpn.conf
```

Ahora probamos si el servicio arranca correctamente:

```bash
$ sudo systemctl start openvpn-client@openvpn.service
```

Si el servicio arranca con normalidad veremos que estamos conectados a la vpn en la barra de tareas que tengamos configurada para tal efecto.

Ahora que todo lo tenemos configurado, solo nos queda que arranque al inicio del sistema. Para ello habilitaremos el servicio:

```bash
$ sudo systemctl enable openvpn-client@openvpn.service
```

Y ya está! el sistema ya está configurado para iniciar tu VPN favorita al inicio!

### CONSEJOS:

Os recomiendo crearos unos `alias` por si queréis iniciar, parar o reiniciar el servicio VPN.

```bash
alias vpnstart='sudo systemctl start openvpn-client@openvpn.service'
alias vpnstop='sudo systemctl stop openvpn-client@openvpn.service'
alias vpnrestart='sudo systemctl restart openvpn-client@openvpn.service'
```

Una última cosa, si queréis deshabilitar el arranque automático porque ya no lo necesitáis, lo haremos como cualquier otro servicio: 

```bash
$ sudo systemctl disable openvpn-client@openvpn.service
```

Déjame en comentarios si te ha sido de ayuda.

Gracias!
