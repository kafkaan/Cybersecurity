# Bypassing Basic Authentication

***

{% hint style="warning" %}
L’**HTTP Verb Tampering** consiste à tester différentes méthodes HTTP pour voir si le serveur/app gère mal certaines d’entre elles.

* Les failles de **mauvaise configuration serveur** sont faciles à détecter (ex. contourner une authentification).
* Les failles de **code mal sécurisé** nécessitent des tests manuels plus poussé
{% endhint %}

***

### :eye: <mark style="color:blue;">Identify</mark>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_add.jpg" alt=""><figcaption></figcaption></figure>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_reset.jpg" alt=""><figcaption></figcaption></figure>

As we do not have any credentials, we will get a `401 Unauthorized` page:

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_unauthorized.jpg" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Exploit</mark>

To try and exploit the page, we need to identify the HTTP request method used by the web application. We can intercept the request in Burp Suite and examine it:&#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_unauthorized_request.jpg" alt=""><figcaption></figcaption></figure>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_change_request.jpg" alt=""><figcaption></figcaption></figure>

Once we do so, we can click `Forward` and examine the page in our browser. Unfortunately, we still get prompted to log in and will get a `401 Unauthorized` page if we don't provide the credentials:

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_reset.jpg" alt=""><figcaption></figcaption></figure>

To see whether the server accepts `HEAD` requests, we can send an `OPTIONS` request to it and see what HTTP methods are accepted, as follows:

```shell-session
mrroboteLiot_1@htb[/htb]$ curl -i -X OPTIONS http://SERVER_IP:PORT/

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

<div align="center" data-full-width="false"><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_HEAD_request.jpg" alt="HEAD_request"></div>

En changeant **POST** en **HEAD**, on contourne l’authentification et on déclenche la fonction **Reset** sans identifiants, ce qui supprime tous les fichiers
