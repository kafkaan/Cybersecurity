# SKILLS ASSESSEMENT

***

## <mark style="color:red;">**Préparation Initiale**</mark>

* **Connexion au domaine cible :**
  *   Modifier le fichier `/etc/hosts` pour ajouter l'entrée cible.

      ```bash
      sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
      ```

***

## <mark style="color:red;">**Question 1 : Sub-Domain/VHost Fuzzing**</mark>

**Objectif :** Identifier les sous-domaines de `academy.htb`.

* **Commandes employées :**
  *   **Sub-Domain Fuzzing (échec) :**

      <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">ffuf -w /SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb:PORT/
      </code></pre>
  *   **VHost Fuzzing :**

      <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">ffuf -w /SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H "Host: FUZZ.academy.htb" -fs 985
      </code></pre>
* **Réponse :** `test`, `archive`, `faculty`

***

## <mark style="color:red;">**Question 2 : Extension Fuzzing**</mark>

**Objectif :** Identifier les extensions de fichiers acceptées.

* **Ajout des sous-domaines au fichier `/etc/hosts`.**
*   **Fuzzing des extensions sur les sous-domaines :**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">ffuf -w SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SUBDOMAIN.academy.htb:PORT/indexFUZZ
    </code></pre>
* **Réponse :** `.php`, `.php7`, `.phps`

***

## <mark style="color:red;">**Question 3 : Identification d’une page spécifique**</mark>

**Objectif :** Trouver une page contenant le texte "You don’t have access!".

*   **Commande de fuzzing récursif :**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">ffuf -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SUBDOMAIN.academy.htb:PORT/FUZZ -recursion -recursion-depth 1 -e .php,.php7,.phps -fs 287
    </code></pre>
* **Observation :**
  * La page d'intérêt est découverte sur `faculty.academy.htb/courses/linux-security.php7`.
* **Réponse :** `http://faculty.academy.htb:PORT/courses/linux-security.php7`

***

## <mark style="color:red;">**Question 4 : Fuzzing des paramètres**</mark>

**Objectif :** Identifier les paramètres acceptés par la page trouvée.

*   **Fuzzing des paramètres :**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">ffuf -w SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:PORT/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774
    </code></pre>
* **Réponse :** `user`, `username`

***

## <mark style="color:red;">**Question 5 : Fuzzing des valeurs des paramètres**</mark>

**Objectif :** Trouver une valeur valide pour le paramètre et récupérer le flag.

*   **Fuzzing des valeurs pour `username` :**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">ffuf -w SecLists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://faculty.academy.htb:PORT/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781
    </code></pre>
*   **Validation de la réponse :**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">curl http://faculty.academy.htb:PORT/courses/linux-security.php7 -X POST -d 'username=harry' -H 'Content-Type: application/x-www-form-urlencoded'
    </code></pre>
* **Réponse :** `HTB{w3b_fuzz1n6_m4573r}`

***

#### <mark style="color:green;">**Résumé des Commandes Principales**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Étape</strong></td><td><strong>Commande</strong></td></tr><tr><td><strong>Sub-Domain Fuzzing</strong></td><td><code>ffuf -w subdomains-top1million-5000.txt -u http://FUZZ.academy.htb:PORT/</code></td></tr><tr><td><strong>VHost Fuzzing</strong></td><td><code>ffuf -w subdomains-top1million-5000.txt -u http://academy.htb:PORT/ -H "Host: FUZZ.academy.htb" -fs 985</code></td></tr><tr><td><strong>Extension Fuzzing</strong></td><td><code>ffuf -w web-extensions.txt -u http://SUBDOMAIN.academy.htb:PORT/indexFUZZ</code></td></tr><tr><td><strong>Page Fuzzing</strong></td><td><code>ffuf -w directory-list-2.3-small.txt -u http://SUBDOMAIN.academy.htb:PORT/FUZZ -recursion -recursion-depth 1 -e .php,.php7,.phps -fs 287</code></td></tr><tr><td><strong>Paramètre Fuzzing</strong></td><td><code>ffuf -w burp-parameter-names.txt -u http://faculty.academy.htb:PORT/courses/linux-security.php7 -X POST -d 'FUZZ=key' -fs 774</code></td></tr><tr><td><strong>Valeur Fuzzing</strong></td><td><code>ffuf -w xato-net-10-million-usernames.txt -u http://faculty.academy.htb:PORT/courses/linux-security.php7 -X POST -d 'username=FUZZ' -fs 781</code></td></tr><tr><td><strong>Flag Extraction</strong></td><td><code>curl http://faculty.academy.htb:PORT/courses/linux-security.php7 -X POST -d 'username=harry' -H 'Content-Type: application/x-www-form-urlencoded'</code></td></tr></tbody></table>

***
