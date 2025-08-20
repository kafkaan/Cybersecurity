# Stored XSS

***

**Stored XSS** (ou XSS persistant). Si notre charge utile XSS injectée est stockée dans la base de données du serveur et récupérée lorsqu'on visite la page, cela signifie que l'attaque XSS est persistante et peut affecter n'importe quel utilisateur qui visite la page.&#x20;

Ce type de XSS est particulièrement dangereux car il touche un public plus large, chaque utilisateur visitant la page étant vulnérable à l'attaque. De plus, le **Stored XSS** peut être difficile à supprimer, car la charge utile doit être retirée de la base de données du serveur.

&#x20; &#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/103/xss_stored_xss.jpg" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">XSS Testing Payloads</mark>

We can test whether the page is vulnerable to XSS with the following basic XSS payload:

```html
<script>alert(window.origin)</script>
```

&#x20; &#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg" alt=""><figcaption></figcaption></figure>

{% code fullWidth="true" %}
```html
<div></div><ul class="list-unstyled" id="todo"><ul><script>alert(window.origin)</script>
</ul></ul>
```
{% endcode %}

{% hint style="warning" %}
Tip: Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of `window.origin` in the alert box, instead of a static value like `1`. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.
{% endhint %}

Certaines versions modernes de navigateurs peuvent bloquer la fonction JavaScript `alert()` dans certains contextes. Pour tester l'existence de vulnérabilités XSS, il est utile de connaître d'autres charges utiles (payloads) :

1. **`<plaintext>`** :
   * Ce payload interrompt le rendu du code HTML après son injection et affiche tout ce qui suit en texte brut.
2. **`<script>print()</script>`** :
   * Ce payload ouvre la boîte de dialogue d'impression du navigateur, une action qui est rarement bloquée.
