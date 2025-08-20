# Sections ELF

## <mark style="color:$danger;">Sections ELF : Rôles et ordre d'exécution</mark>

### <mark style="color:blue;">1. Sections de métadonnées (chargées en premier)</mark>

#### `.interp` (Section 0)

* **Rôle** : Contient le chemin vers l'interpréteur dynamique (généralement `/lib/ld-linux.so.2`)
* **Contenu** : Chaîne de caractères indiquant quel loader utiliser
* **Quand** : Lu par le kernel au moment du chargement du programme

#### `.note.ABI-tag` (Section 1)

* **Rôle** : Informations sur la compatibilité ABI (Application Binary Interface)
* **Contenu** : Version du système d'exploitation requis
* **Quand** : Vérifié par le loader avant l'exécution

#### `.note.gnu.build-id` (Section 2)

* **Rôle** : Identifiant unique de compilation
* **Contenu** : Hash unique pour identifier cette version du binaire
* **Quand** : Utilisé par les debuggers et outils de développement

***

### <mark style="color:blue;">2. Sections de liaison dynamique</mark>

#### `.gnu.hash` (Section 3)

* **Rôle** : Table de hachage pour accélération de la résolution de symboles
* **Contenu** : Hash des noms de symboles
* **Quand** : Utilisée par le loader pour trouver rapidement les symboles

#### `.dynsym` (Section 4)

* **Rôle** : Table des symboles dynamiques (fonctions et variables externes)
* **Contenu** : Informations sur les symboles à résoudre dynamiquement
* **Quand** : Consultée pendant la liaison dynamique

#### `.dynstr` (Section 5)

* **Rôle** : Chaînes de caractères des symboles dynamiques
* **Contenu** : Noms des fonctions, bibliothèques, etc.
* **Quand** : Utilisée avec `.dynsym` pour identifier les symboles

#### `.gnu.version` (Section 6) et `.gnu.version_r` (Section 7)

* **Rôle** : Informations de versioning des symboles
* **Contenu** : Versions requises des symboles et bibliothèques
* **Quand** : Vérifiée pendant la liaison dynamique

#### `.rel.dyn` (Section 8) et `.rel.plt` (Section 9)

* **Rôle** : Tables de relocation
* **Contenu** : Instructions pour modifier les adresses au moment du chargement
* **Quand** : Appliquées par le loader dynamique

***

### <mark style="color:blue;">3. Sections de code exécutable (ordre d'exécution)</mark>

#### `.init` (Section 10) - **PREMIÈRE À S'EXÉCUTER**

* **Rôle** : Code d'initialisation avant main()
* **Contenu** : Instructions d'initialisation du runtime C
* **Quand** : Exécutée automatiquement avant main()
* **Appelée par** : Le loader, puis appelle les constructeurs

#### `.plt` (Section 11) - Procedure Linkage Table

* **Rôle** : Trampoline pour les appels de fonctions externes
* **Contenu** : Code de redirection vers les vraies fonctions
* **Quand** : Utilisée lors des appels à des fonctions de bibliothèques
* **Appelée par** : Le code dans `.text` quand il appelle une fonction externe

#### `.text` (Section 12) - **CODE PRINCIPAL**

* **Rôle** : Code principal du programme (main() et autres fonctions)
* **Contenu** : Instructions machine du programme
* **Quand** : Exécutée après `.init`, contient le point d'entrée main()
* **Appelée par** : Le runtime après l'initialisation

#### `.fini` (Section 13) - **DERNIÈRE À S'EXÉCUTER**

* **Rôle** : Code de finalisation après main()
* **Contenu** : Nettoyage et destructeurs
* **Quand** : Exécutée automatiquement après la fin de main()
* **Appelée par** : Le runtime C lors de la terminaison

***

### <mark style="color:blue;">4. Sections de données</mark>

#### `.rodata` (Section 14)

* **Rôle** : Données en lecture seule (constantes, chaînes littérales)
* **Contenu** : `const char* msg = "Hello";` par exemple
* **Quand** : Accessible pendant toute l'exécution

#### `.eh_frame_hdr` (Section 15) et `.eh_frame` (Section 16)

* **Rôle** : Informations pour la gestion des exceptions
* **Contenu** : Tables de dépilage de pile pour exceptions C++
* **Quand** : Utilisées lors du lancement d'exceptions

#### `.gcc_except_table` (Section 17)

* **Rôle** : Table des exceptions GCC
* **Contenu** : Informations sur les blocs try/catch
* **Quand** : Consultée lors de la propagation d'exceptions

***

### <mark style="color:blue;">5. Sections d'initialisation des données</mark>

#### `.init_array` (Section 18)

* **Rôle** : Tableau de pointeurs vers les constructeurs
* **Contenu** : Adresses des fonctions à appeler avant main()
* **Quand** : Parcourue par `.init` pour appeler les constructeurs

#### `.fini_array` (Section 19)

* **Rôle** : Tableau de pointeurs vers les destructeurs
* **Contenu** : Adresses des fonctions à appeler après main()
* **Quand** : Parcourue par `.fini` pour appeler les destructeurs

#### `.jcr` (Section 20)

* **Rôle** : Java Class Registration (pour compatibilité GCJ)
* **Contenu** : Informations pour l'intégration Java (souvent vide)

***

### <mark style="color:blue;">6. Sections de liaison dynamique runtime</mark>

#### `.dynamic` (Section 21)

* **Rôle** : Informations pour le loader dynamique
* **Contenu** : Références vers autres sections, bibliothèques requises
* **Quand** : Consultée par le loader au démarrage

#### `.got` (Section 22) et `.got.plt` (Section 23)

* **Rôle** : Global Offset Table - adresses des variables/fonctions globales
* **Contenu** : Pointeurs vers les vraies adresses des symboles
* **Quand** : Remplies par le loader, utilisées pendant l'exécution

***

### <mark style="color:blue;">7. Sections de données runtime</mark>

#### `.data` (Section 24)

* **Rôle** : Données globales initialisées
* **Contenu** : Variables globales avec valeur initiale
* **Quand** : Copiées du fichier vers la mémoire au chargement

#### `.bss` (Section 25)

* **Rôle** : Données globales non initialisées
* **Contenu** : Variables globales sans valeur initiale (mises à zéro)
* **Quand** : Allouées et initialisées à zéro au chargement

#### `.comment` (Section 26)

* **Rôle** : Informations de compilation
* **Contenu** : Version du compilateur, options utilisées
* **Quand** : Informative uniquement, pas chargée en mémoire

***

### <mark style="color:red;">Ordre d'exécution résumé :</mark>

1. **Chargement** : Kernel lit `.interp`, charge le loader dynamique
2. **Liaison** : Loader consulte `.dynamic`, `.dynsym`, `.dynstr`, remplit `.got`
3. **Initialisation** : `.init` s'exécute, appelle les fonctions dans `.init_array`
4. **Exécution principale** : `.text` s'exécute (main() et autres fonctions)
5. **Finalisation** : `.fini` s'exécute, appelle les fonctions dans `.fini_array`

Les sections `.plt`, `.got` sont utilisées tout au long de l'exécution pour les appels de fonctions externes.
