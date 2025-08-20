# SKILLS ASSESSEMENT

## <mark style="color:red;">Using Web Proxies HackTheBox</mark> <a href="#id-5b02" id="id-5b02"></a>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*q-AebaNiti5UAfZwRQniRg.png" alt="" height="231" width="700"><figcaption></figcaption></figure>

So, let us change the ip parameter’s value from 1 to **;ls;**

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*kh11dWAYchvNZ409rCeuGA.png" alt="" height="235" width="700"><figcaption></figcaption></figure>

Try intercepting the ping request on the server shown above, and change the post data similarly to what we did in this section. Change the command to read ‘flag.txt’

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*YtiofC7aea6armpytt7qyw.png" alt="" height="179" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:249/1*ey3LQ6yEMaWi4aOli9bogQ.png" alt="" height="37" width="249"><figcaption></figcaption></figure>

Try using request repeating to be able to quickly test commands. With that, try looking for the other flag.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*85KL2kSBoQWTgP6hRW_5Cw.png" alt="" height="381" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*Jt8tiJ6JUq9PBeRL_Bs8aA.png" alt="" height="270" width="700"><figcaption></figcaption></figure>

The **string** found in the attached file has been **encoded several times** with various encoders. Try to use the **decoding tools** we discussed to decode it and get the flag.

string:

```
VTJ4U1VrNUZjRlZXVkVKTFZrWkdOVk5zVW10aFZYQlZWRmh3UzFaR2NITlRiRkphWld0d1ZWUllaRXRXUm10M1UyeFNUbVZGY0ZWWGJYaExWa1V3ZVZOc1VsZGlWWEJWVjIxNFMxWkZNVFJUYkZKaFlrVndWVmR0YUV0V1JUQjNVMnhTYTJGM1BUMD0=
```

BurpSuite -> decoder

4x base64 -> ASCII hex -> Binary-> remove ‘%’

HTB{3nc0d1n6\_n1nj4}

***

## <mark style="color:red;">Proxying Tools</mark> <a href="#id-2881" id="id-2881"></a>

_Try running ‘auxiliary/scanner/http/**http\_put**’ in **Metasploit** on any website, while routing the **traffic through Burp**. Once you view the **requests sent**, what is the **last line** in the request?_

> **msfconsole**
>
> msf6 >**search http\_put**
>
> msf6 >**use 0**
>
> msf6 >**set RHOSTS 206.189.117.48**
>
> msf6 >**set RPORT 30301**
>
> msf6 >**set PROXIES HTTP:127.0.0.1:8080**
>
> msf6 >**run**

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*BXjJJEUYtasHK1b6oXHZsg.png" alt="" height="204" width="700"><figcaption></figcaption></figure>

***

## <mark style="color:red;">Burp Intruder</mark> <a href="#e0cc" id="e0cc"></a>

Use Burp Intruder to fuzz for ‘.html’ files under the /admin directory, to find a file containing the flag.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*f7hJvBphwK8SHInBDqBY9A.png" alt="" height="478" width="700"><figcaption></figcaption></figure>

***

## <mark style="color:red;">ZAP Fuzzer</mark> <a href="#a098" id="a098"></a>

_The directory we found above sets the cookie to the md5 hash of the username, as we can see the md5 cookie in the request for the (guest) user. Visit ‘/skills/’ to get a request with a cookie, then try to use ZAP Fuzzer to fuzz the cookie for different md5 hashed usernames to get the flag. Use the “top-usernames-shortlist.txt” wordlist from Seclists._

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*TaLoqKtTF2S7jkoac9KRXA.png" alt="" height="248" width="700"><figcaption></figcaption></figure>

Intercept website request on zap

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*FtV_ArSW6Ek16sNrUcvv5g.png" alt="" height="53" width="700"><figcaption></figcaption></figure>

fuzzer request:

Right mouse click on cookie request -> Fuzz

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*LUbUWnRwG-3Ag7_o5xHszg.png" alt="" height="363" width="700"><figcaption></figcaption></figure>

Set wordlist:top-usernames-shortlist.txt

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*RVlcHVyhZedlie90g--y-w.png" alt="" height="372" width="700"><figcaption></figcaption></figure>

Set Processors: Hash MD5

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*iPT50LyG3xd9ETrhhJ-7ag.png" alt="" height="332" width="700"><figcaption></figcaption></figure>

Start Fuzz.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*ttoV3TNwOHs3mZkan_0-DA.png" alt="" height="60" width="700"><figcaption></figcaption></figure>

cookie=ee11cbb19052e40b07aac0ca060c23ee = user

Try to use hash as cookie

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*ESO1FCtCpBK7muZz2iJvew.png" alt="" height="405" width="700"><figcaption></figcaption></figure>

***

## <mark style="color:red;">ZAP Scanner</mark> <a href="#b47f" id="b47f"></a>

Run ZAP Scanner on the target above to identify directories and potential vulnerabilities. Once you find the high-level vulnerability, try to use it to read the flag at ‘/flag.txt’

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*6PRTpXK4AKoaxPlrxJnmZA.png" alt="" height="349" width="700"><figcaption></figcaption></figure>

Remote OS Command Injection

> [http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fetc%2Fpasswd%26](http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fetc%2Fpasswd%26)
>
> [http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fflag.txt%26](http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fflag.txt%26)

<figure><img src="https://miro.medium.com/v2/resize:fit:390/1*jjPerfAM7E1eYfgGV6SxLg.png" alt="" height="168" width="390"><figcaption></figcaption></figure>

## <mark style="color:red;">Skills Assessment — Using Web Proxies</mark> <a href="#d2d2" id="d2d2"></a>

_The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag._

_Nota: intercerta o request da pagina /lucky.php, na response apaga o disable e em seguida clica no button e intercetamos o request do button e enviamos para o repeater onde enviaremos este request varias vezes ate receber a flag_

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*dNQfPJltKTM0QiVnE1-WHQ.png" alt="" height="432" width="700"><figcaption></figcaption></figure>

_The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer._

C[yberChef](https://gchq.github.io/CyberChef/) ->from hex -> from base64

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*2OZyZ9Kqwemhq0-9tN7z1Q.png" alt="" height="267" width="700"><figcaption></figcaption></figure>

_Once you decode the cookie, you will notice that it is **only 31 characters long,** which appears to be an md5 hash missing its last character. So, try to fuzz the last character of the decoded **md5 cooki**e with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the “**alphanum-case.txt**” wordlist from Seclist for the payload)_

Burp:

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*ebYCp506c4ydzpMLjX7GRQ.png" alt="" height="483" width="700"><figcaption></figcaption></figure>

run the payload and get da flag:

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*ccVCQ1Gy7Lcjjh-o9YBkCQ.png" alt="" height="197" width="700"><figcaption></figcaption></figure>

You are using the ‘auxiliary/scanner/http/coldfusion\_locale\_traversal’ tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the ‘XXXXX’ directory being called in ‘/XXXXX/administrator/..’?

> msf6 >**search coldfusion\_locale\_traversa**l
>
> msf6 >**use 0**
>
> msf6 >**set RHOSTS 167.71.140.137**
>
> msf6 >**set RPORT 30650**
>
> msf6 >**set PROXIES HTTP:127.0.0.1:8080**
>
> msf6 >**exploit**

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*jeE9CHljhrsfqT30oGRqzQ.png" alt="" height="533" width="700"><figcaption></figcaption></figure>
