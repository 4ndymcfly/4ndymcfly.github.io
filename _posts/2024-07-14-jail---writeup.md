---
redirect_from:
  - /posts/JAIL-WriteUp/

title: "Jail - WriteUp"
date: Sun Jul 14 2024 10:15:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Windows]
tags: [ctf, nmap, htb, smb, ldap, windows, apache, bof, ssh, bash]
image: /assets/img/htb-writeups/Pasted-image-20240226131626.png
---

{% include machine-info.html
  machine="Jail"
  os="Windows"
  difficulty="Insane"
  platform="HTB"
%}

![Jail](/assets/img/htb-writeups/Pasted-image-20240226131626.png)

Tags:

-----

![JAIL](/assets/img/htb-writeups/Pasted-image-20240226131626.png)

Jail o "la cárcel", como su nombre lo indica, implica escapar de múltiples entornos sandbox y escalar entre múltiples cuentas de usuario. Definitivamente es una de las máquinas más desafiantes de Hack The Box y requiere conocimientos bastante avanzados en varias áreas para completarla.

-------
#### ENUM

NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Feb 26 13:19:08 2024 as: nmap -sCV -p 22,80,111,2049,7411,20048 --stylesheet=https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/stable/nmap-bootstrap.xsl -oN targeted -oX targetedXML 10.129.215.77
Nmap scan report for 10.129.215.77
Host is up (0.041s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd:ec:19:7c:da:dc:16:e2:a3:9d:42:f3:18:4b:e6:4d (RSA)
|   256 af:94:9f:2f:21:d0:e0:1d:ae:8e:7f:1d:7b:d7:42:ef (ECDSA)
|_  256 6b:f8:dc:27:4f:1c:89:67:a4:67:c5:ed:07:53:af:97 (ED25519)
80/tcp    open  http       Apache httpd 2.4.6 ((CentOS))
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS)
111/tcp   open  rpcbind    2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      20048/tcp   mountd
|   100005  1,2,3      20048/tcp6  mountd
|   100005  1,2,3      20048/udp   mountd
|   100005  1,2,3      20048/udp6  mountd
|   100021  1,3,4      34325/tcp   nlockmgr
|   100021  1,3,4      35422/udp6  nlockmgr
|   100021  1,3,4      42059/tcp6  nlockmgr
|   100021  1,3,4      50088/udp   nlockmgr
|   100024  1          32957/tcp6  status
|   100024  1          41588/udp6  status
|   100024  1          42764/udp   status
|   100024  1          45715/tcp   status
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl    3 (RPC #100227)
7411/tcp  open  daqstream?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    OK Ready. Send USER command.
20048/tcp open  mountd     1-3 (RPC #100005)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7411-TCP:V=7.94SVN%I=7%D=2/26%Time=65DC81C2%P=x86_64-pc-linux-gnu%r
SF:(NULL,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(GenericLines
SF:,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(GetRequest,1D,"OK
SF:\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(HTTPOptions,1D,"OK\x20Re
SF:ady\.\x20Send\x20USER\x20command\.\n")%r(RTSPRequest,1D,"OK\x20Ready\.\
SF:x20Send\x20USER\x20command\.\n")%r(RPCCheck,1D,"OK\x20Ready\.\x20Send\x
SF:20USER\x20command\.\n")%r(DNSVersionBindReqTCP,1D,"OK\x20Ready\.\x20Sen
SF:d\x20USER\x20command\.\n")%r(DNSStatusRequestTCP,1D,"OK\x20Ready\.\x20S
SF:end\x20USER\x20command\.\n")%r(Help,1D,"OK\x20Ready\.\x20Send\x20USER\x
SF:20command\.\n")%r(SSLSessionReq,1D,"OK\x20Ready\.\x20Send\x20USER\x20co
SF:mmand\.\n")%r(TerminalServerCookie,1D,"OK\x20Ready\.\x20Send\x20USER\x2
SF:0command\.\n")%r(TLSSessionReq,1D,"OK\x20Ready\.\x20Send\x20USER\x20com
SF:mand\.\n")%r(Kerberos,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n"
SF:)%r(SMBProgNeg,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(X11
SF:Probe,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(FourOhFourRe
SF:quest,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(LPDString,1D
SF:,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(LDAPSearchReq,1D,"OK
SF:\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(LDAPBindReq,1D,"OK\x20Re
SF:ady\.\x20Send\x20USER\x20command\.\n")%r(SIPOptions,1D,"OK\x20Ready\.\x
SF:20Send\x20USER\x20command\.\n")%r(LANDesk-RC,1D,"OK\x20Ready\.\x20Send\
SF:x20USER\x20command\.\n")%r(TerminalServer,1D,"OK\x20Ready\.\x20Send\x20
SF:USER\x20command\.\n")%r(NCP,1D,"OK\x20Ready\.\x20Send\x20USER\x20comman
SF:d\.\n")%r(NotesRPC,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r
SF:(JavaRMI,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(WMSReques
SF:t,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(oracle-tns,1D,"O
SF:K\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(ms-sql-s,1D,"OK\x20Read
SF:y\.\x20Send\x20USER\x20command\.\n")%r(afp,1D,"OK\x20Ready\.\x20Send\x2
SF:0USER\x20command\.\n")%r(giop,1D,"OK\x20Ready\.\x20Send\x20USER\x20comm
SF:and\.\n");
```

##### NOTA:
La resolución se deja aparcada temporalmente por que es necesario hacer un Buffer Overflow para poder acabarla y no entra en el temario actual del OSCP.
---

**Última actualización**: 2024-07-14<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
