# Bypassing Security Filters

***

{% hint style="warning" %}
L'autre type, plus courant, de vulnérabilité de manipulation des verbes HTTP est causé par des erreurs de codage lors du développement de l'application web. Ces erreurs entraînent une couverture incomplète des méthodes HTTP pour certaines fonctionnalités, notamment dans les filtres de sécurité qui détectent les requêtes malveillantes. Par exemple, si un filtre de sécurité détecte les injections uniquement dans les paramètres POST (comme `$_POST['parameter']`), il peut être contourné en modifiant la méthode de la requête en GET.
{% endhint %}

***

### <mark style="color:blue;">Identify</mark>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_malicious_request.jpg" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Exploit</mark>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_GET_request.jpg" alt=""><figcaption></figcaption></figure>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_injected_request.jpg" alt=""><figcaption></figcaption></figure>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_filter_bypass.jpg" alt=""><figcaption></figcaption></figure>

Then, we can once again change the request method to a `GET` request:&#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_filter_bypass_request.jpg" alt=""><figcaption></figcaption></figure>

Once we send our request, we see that this time both `file1` and `file2` were created:

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_after_filter_bypass.jpg" alt=""><figcaption></figcaption></figure>
