---
cover: ../../.gitbook/assets/XSS-attacks-what-is-cross-site-scripting.webp
coverY: 204.65066666666667
---

# XSS

***

## <mark style="color:red;">**Introduction**</mark>

* Les applications web modernes sont souvent vulnérables aux failles de sécurité, dont le **Cross-Site Scripting (XSS)**.
* Une vulnérabilité XSS exploite une mauvaise validation des entrées utilisateur pour injecter du code **JavaScript** malveillant dans la page, exécuté côté client.

***

## <mark style="color:red;">**Qu'est-ce que le XSS ?**</mark>

* Les applications web reçoivent du code HTML depuis le serveur et le rendent sur le navigateur.
* Une application vulnérable **ne valide pas correctement les entrées utilisateur**, permettant à un attaquant d’injecter du JavaScript malveillant.
* **Impact** :
  * Affecte uniquement l'utilisateur qui exécute la faille (côté client).
  * Le serveur n'est pas directement affecté.
  * **Risque** : Probabilité élevée + impact faible = risque moyen. Il reste essentiel de détecter, corriger et prévenir ces vulnérabilités.

***

## <mark style="color:red;">**Risques associés au XSS**</mark>

* Permet d'exécuter une large gamme d'attaques via JavaScript :
  * **Vol de cookies de session** pour usurper l'identité.
  * **Appels API malveillants** (ex. : changer le mot de passe).
  * **Autres exemples** : minage de cryptomonnaies, affichage de publicités non désirées.
* Limitations :
  * Confiné au moteur JavaScript du navigateur.
  * Ne peut pas exécuter de code système (sauf exploit de vulnérabilités plus profondes).
  * Limitations de sécurité modernes (sandboxing, politique du même domaine).

***

#### <mark style="color:green;">**Exemples célèbres d'attaques XSS**</mark>

1. **Samy Worm (2005)** : Un ver XSS sur MySpace a infecté plus d’un million d’utilisateurs en 24h.
   * Postait un message contenant un script malveillant, se propageant automatiquement.
2. **TweetDeck XSS (2014)** : Une faille a permis de retweeter un message plus de 38,000 fois en 2 minutes.
3. **Google et Apache** :
   * Google a corrigé plusieurs failles XSS sur son moteur de recherche (ex. : 2019).
   * Apache a subi une exploitation active d’une faille XSS pour voler des mots de passe.

***

## <mark style="color:red;">**Types de vulnérabilités XSS**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Type</strong></td><td><strong>Description</strong></td></tr><tr><td><strong>Stored (Persistent)</strong></td><td>L'entrée utilisateur est stockée dans la base de données et affichée ultérieurement (ex. : commentaires).</td></tr><tr><td><strong>Reflected (Non-Persistent)</strong></td><td>L'entrée utilisateur est affichée immédiatement après traitement par le serveur, sans stockage (ex. : résultats de recherche).</td></tr><tr><td><strong>DOM-based XSS</strong></td><td>Traité uniquement côté client sans interaction avec le serveur (ex. : paramètres HTTP ou balises anchor).</td></tr></tbody></table>

***

## <mark style="color:red;">**Prévention des vulnérabilités XSS**</mark>

1. **Sanitisation des entrées utilisateur** :
   * Valider toutes les entrées avant traitement.
   * Encoder les caractères spéciaux pour éviter leur interprétation en tant que code.
2. **Utilisation d’en-têtes de sécurité** :
   * `Content-Security-Policy` (CSP) pour limiter les scripts exécutables.
3. **Frameworks sécurisés** :
   * Utiliser des bibliothèques qui intègrent des protections XSS par défaut.
4. **Tests réguliers** :
   * Scanner les applications pour détecter les vulnérabilités XSS.

***
