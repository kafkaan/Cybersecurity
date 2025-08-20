# Découverte des Vulnérabilités XSS

***

## <mark style="color:red;">**Qu’est-ce qu’une vulnérabilité XSS ?**</mark>

* Injection de code JavaScript malveillant dans une page web pour exécution côté client.
* Les trois types d’attaques XSS :
  * **Stored (Persistant)** : L’entrée malveillante est stockée côté serveur (ex. : commentaire).
  * **Reflected (Non-persistant)** : L’entrée est injectée mais non stockée (ex. : barre de recherche).
  * **DOM-based** : L’entrée est manipulée uniquement côté client, sans atteindre le serveur.

***

## <mark style="color:red;">**Méthodes de Détection des Vulnérabilités XSS**</mark>

**1. Détection Automatique**

* Outils : Nessus, Burp Pro, ZAP (payants), et open-source comme **XSStrike**, **Brute XSS**, **XSSer**.
* Fonctionnement :
  * **Scan passif** : Analyse le code client pour identifier des vulnérabilités DOM-based.
  * **Scan actif** : Envoie des payloads pour tenter d’exploiter les failles XSS.
*   Exemple avec XSStrike :

    ```bash
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
    ```

    * Résultats : Identifie les paramètres vulnérables et génère des payloads XSS efficaces.

***

## <mark style="color:red;">**2. Détection Manuelle**</mark>

* **Payloads XSS** :
  * Testez différentes charges utiles, comme celles disponibles dans les bases comme **PayloadAllTheThings** ou **PayloadBox**.
  * Payloads classiques :
    * `<script>alert('XSS')</script>` (alerte classique).
    * `<img src=x onerror=alert('XSS')>` (via attribut HTML).
    * `<style>@import('javascript:alert("XSS")')</style>` (via CSS).
  * Les payloads peuvent cibler des champs HTML ou des en-têtes HTTP (ex. : Cookie, User-Agent).
* **Code Review** :
  * Analysez le code front-end (DOM-based) et back-end pour comprendre comment les entrées sont traitées.
  * Vérifiez les sources (input) et les exécuteurs (sink) du code.
