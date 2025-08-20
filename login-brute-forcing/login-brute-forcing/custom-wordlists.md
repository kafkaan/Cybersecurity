# Custom Wordlists

## <mark style="color:red;">**1. Introduction aux Wordlists Personnalisées**</mark>

Les **wordlists** préexistantes comme _rockyou_ ou _SecLists_ sont souvent utilisées pour les attaques par force brute. Cependant, elles peuvent s'avérer inefficaces et lentes, surtout lorsqu'il s'agit de cibler des individus ou des organisations spécifiques. Un mot de passe générique peut ne pas correspondre à des modèles spécifiques adoptés par un utilisateur ou une entreprise. C'est là qu'interviennent les **wordlists personnalisées**, créées en fonction d'informations spécifiques sur la cible.

***

## <mark style="color:red;">**2. Scénarios où les Wordlists Personnalisées sont Cruciales**</mark>

Imaginons une attaque visant un utilisateur nommé **Thomas Edison**. Si nous utilisons une **wordlist générique**, comme celles qui sont basées sur les 10 millions de noms d'utilisateurs de Xato, nous avons peu de chances de trouver le bon nom d'utilisateur. Cependant, si nous personnalisons notre liste avec des combinaisons basées sur son prénom, son nom, ou même des conventions spécifiques à son entreprise, nous augmentons considérablement les chances de succès.

***

## <mark style="color:red;">**3. Username Anarchy**</mark>

Les **noms d'utilisateurs** ne suivent pas toujours un format simple. Par exemple, avec un nom comme "Jane Smith", il existe des milliers de variations possibles :

* `janesmith`, `smithjane`, `j.smith`, `jane.s`, etc.
* Ajout de l'initiale du prénom ou du nom de famille.
* Utilisation du leetspeak (`j4n3`, `5m1th`, `j@n3_smith`).

**Username Anarchy** est un outil permettant de générer automatiquement ces combinaisons. Voici comment l'utiliser :

1.  **Installation de Ruby et du script Username Anarchy** :

    ```bash
    sudo apt install ruby -y
    git clone https://github.com/urbanadventurer/username-anarchy.git
    cd username-anarchy
    ```
2.  **Exécution pour générer les noms d'utilisateur** :

    ```bash
    ./username-anarchy Jane Smith > jane_smith_usernames.txt
    ```

**Exemples de résultats dans le fichier `jane_smith_usernames.txt`** :

* Combinaisons basiques : `janesmith`, `smithjane`, `j.smith`
* Initiales : `js`, `j.s`, `s.j.`
* Variations avec des chiffres ou symboles : `jane_smith99`, `j@nesmith`

***

## <mark style="color:red;">**4. CUPP (Common User Password Profiler)**</mark>

Après avoir généré les noms d'utilisateur, la prochaine étape consiste à créer une **wordlist de mots de passe personnalisés**. **CUPP** est un outil qui crée des listes de mots de passe basées sur des informations spécifiques à la cible (date de naissance, prénoms, surnoms, etc.).

**Collecte des informations personnelles sur la cible** (par exemple Jane Smith) :

* **Prénom** : Jane
* **Nom de famille** : Smith
* **Surnom** : Janey
* **Date de naissance** : 11/12/1990
* **Nom du partenaire** : Jim
* **Animal de compagnie** : Spot
* **Entreprise** : AHI
* **Couleur préférée** : Bleu

**Exécution de CUPP pour générer un fichier de mots de passe personnalisé** :

```bash
sudo apt install cupp -y
cupp -i
```

Lorsque CUPP vous demande des informations sur la cible, vous entrez les données collectées pour générer un fichier de mots de passe. Exemple d'entrée :

* `First Name: Jane`
* `Surname: Smith`
* `Nickname: Janey`
* `Birthdate: 11121990`

CUPP génère des mots de passe comme :

* **Variations de prénoms** : `jane`, `Jane`
* **Mots de passe inversés** : `enaj`, `enaJ`
* **Variations basées sur la date de naissance** : `jane1990`, `smith1211`
* **Ajout de caractères spéciaux et de chiffres** : `jane!`, `jane123`, `smith@2024`

***

## <mark style="color:red;">**5. Filtrage selon les politiques de mot de passe**</mark>

Si la cible a des politiques de mot de passe spécifiques (ex. longueur minimale, lettres majuscules et minuscules, chiffres, caractères spéciaux), vous pouvez filtrer votre wordlist avec **grep** :

Exemple pour filtrer une liste de mots de passe avec une politique spécifique (minimum 6 caractères, au moins 1 lettre majuscule, 1 minuscule, 1 chiffre, et 2 caractères spéciaux) :

{% code overflow="wrap" fullWidth="true" %}
```bash
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```
{% endcode %}

***

## <mark style="color:red;">**6. Brute-Force avec Hydra**</mark>

Une fois que vous avez généré et filtré vos listes de noms d'utilisateurs et de mots de passe, vous pouvez utiliser **Hydra** pour lancer l'attaque par force brute :

{% code overflow="wrap" fullWidth="true" %}
```bash
hydra -L usernames.txt -P jane-filtered.txt IP -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
```
{% endcode %}

