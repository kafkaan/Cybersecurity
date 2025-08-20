# Reflected XSS

***

Il existe deux types de vulnérabilités XSS non persistantes : le <mark style="color:orange;">**Reflected XSS**</mark>, qui est traité par le serveur back-end, et le **DOM-based XSS**, qui est entièrement traité côté client et ne parvient jamais au serveur back-end. Contrairement au **Persistent XSS**, les vulnérabilités XSS non persistantes sont temporaires et ne persistent pas lors des actualisations de la page. Ainsi, nos attaques n'affectent que l'utilisateur ciblé et ne toucheront pas les autres utilisateurs qui visitent la page.

{% hint style="warning" %}
Les vulnérabilités **Reflected XSS** se produisent lorsque notre entrée atteint le serveur back-end et nous est renvoyée sans être filtrée ou assainie. Il existe de nombreux cas où notre entrée complète pourrait nous être renvoyée, comme dans les messages d'erreur ou les messages de confirmation. Dans ces cas, nous pouvons tenter d'utiliser des charges utiles XSS pour voir si elles s'exécutent. Cependant, comme ces messages sont généralement temporaires, une fois que nous quittons la page, ils ne s'exécuteront plus, et donc, ce sont des attaques **non persistantes**.
{% endhint %}

Nous pouvons démarrer le serveur ci-dessous pour pratiquer sur une page web vulnérable à une vulnérabilité de **Reflected XSS**. C'est une application To-Do List similaire à celle que nous avons pratiquée dans la section précédente. Nous pouvons essayer d'ajouter n'importe quelle chaîne de test pour voir comment elle est traitée.

<figure><img src="../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

As we can see, we get `Task 'test' could not be added.`, which includes our input `test` as part of the error message. If our input was not filtered or sanitized, the page might be vulnerable to XSS. We can try the same XSS payload we used in the previous section and click `Add`:

<figure><img src="../../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

Once we click `Add`, we get the alert pop-up:

&#x20; &#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg" alt=""><figcaption></figcaption></figure>

In this case, we see that the error message now says **`Task '' could not be added.`**. Since our payload is wrapped with a **`<script>`** tag, it does not get rendered by the browser, so we get empty single quotes **`''`** instead. We can once again view the page source to confirm that the error message includes our XSS payload:

{% code overflow="wrap" fullWidth="true" %}
```html
<div></div><ul class="list-unstyled" id="todo"><div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div></ul>
```
{% endcode %}

If we visit the `Reflected` page again, the error message no longer appears, and our XSS payload is not executed, which means that this XSS vulnerability is indeed `Non-Persistent`.

`But if the XSS vulnerability is Non-Persistent, how would we target victims with it?`

This depends on which HTTP request is used to send our input to the server. We can check this through the Firefox `Developer Tools` by clicking \[`CTRL+Shift+I`] and selecting the `Network` tab. Then, we can put our `test` payload again and click `Add` to send it:

<figure><img src="../../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

As we can see, the first row shows that our request was a `GET` request. `GET` request sends their parameters and data as part of the URL. So, `to target a user, we can send them a URL containing our payload`. To get the URL, we can copy the URL from the URL bar in Firefox after sending our XSS payload, or we can right-click on the `GET` request in the `Network` tab and select `Copy>Copy URL`. Once the victim visits this URL, the XSS payload would execute:
