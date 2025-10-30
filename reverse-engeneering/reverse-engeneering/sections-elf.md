# Sections ELF

## <mark style="color:red;">Sections ELF : Rôles et ordre d'exécution</mark>

### <mark style="color:blue;">1. Sections de métadonnées (chargées en premier)</mark>

#### <mark style="color:green;">`.interp`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 0)</mark>

* **Rôle** : Contient le chemin vers l'interpréteur dynamique (généralement `/lib/ld-linux.so.2`)
* **Contenu** : Chaîne de caractères indiquant quel loader utiliser
* **Quand** : Lu par le kernel au moment du chargement du programme

#### <mark style="color:green;">`.note.ABI-tag`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 1)</mark>

* **Rôle** : Informations sur la compatibilité ABI (Application Binary Interface)
* **Contenu** : Version du système d'exploitation requis
* **Quand** : Vérifié par le loader avant l'exécution

#### <mark style="color:green;">`.note.gnu.build-id`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 2)</mark>

* **Rôle** : Identifiant unique de compilation
* **Contenu** : Hash unique pour identifier cette version du binaire
* **Quand** : Utilisé par les debuggers et outils de développement

***

### <mark style="color:blue;">2. Sections de liaison dynamique</mark>

#### <mark style="color:green;">`.gnu.hash`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 3)</mark>

* **Rôle** : Table de hachage pour accélération de la résolution de symboles
* **Contenu** : Hash des noms de symboles
* **Quand** : Utilisée par le loader pour trouver rapidement les symboles

#### <mark style="color:green;">`.dynsym`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 4)</mark>

* **Rôle** : Table des symboles dynamiques (fonctions et variables externes)
* **Contenu** : Informations sur les symboles à résoudre dynamiquement
* **Quand** : Consultée pendant la liaison dynamique

#### <mark style="color:green;">`.dynstr`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 5)</mark>

* **Rôle** : Chaînes de caractères des symboles dynamiques
* **Contenu** : Noms des fonctions, bibliothèques, etc.
* **Quand** : Utilisée avec `.dynsym` pour identifier les symboles

#### <mark style="color:green;">`.gnu.version`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 6) et</mark> <mark style="color:green;"></mark><mark style="color:green;">`.gnu.version_r`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 7)</mark>

* **Rôle** : Informations de versioning des symboles
* **Contenu** : Versions requises des symboles et bibliothèques
* **Quand** : Vérifiée pendant la liaison dynamique

#### <mark style="color:green;">`.rel.dyn`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 8) et</mark> <mark style="color:green;"></mark><mark style="color:green;">`.rel.plt`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 9)</mark>

* **Rôle** : Tables de relocation
* **Contenu** : Instructions pour modifier les adresses au moment du chargement
* **Quand** : Appliquées par le loader dynamique

***

### <mark style="color:blue;">3. Sections de code exécutable (ordre d'exécution)</mark>

#### <mark style="color:green;">`.init`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 10) -</mark> <mark style="color:green;"></mark><mark style="color:green;">**PREMIÈRE À S'EXÉCUTER**</mark>

* **Rôle** : Code d'initialisation avant main()
* **Contenu** : Instructions d'initialisation du runtime C
* **Quand** : Exécutée automatiquement avant main()
* **Appelée par** : Le loader, puis appelle les constructeurs

#### <mark style="color:green;">`.plt`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 11) - Procedure Linkage Table</mark>

* **Rôle** : Trampoline pour les appels de fonctions externes
* **Contenu** : Code de redirection vers les vraies fonctions
* **Quand** : Utilisée lors des appels à des fonctions de bibliothèques
* **Appelée par** : Le code dans `.text` quand il appelle une fonction externe

#### <mark style="color:green;">`.text`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 12) -</mark> <mark style="color:green;"></mark><mark style="color:green;">**CODE PRINCIPAL**</mark>

* **Rôle** : Code principal du programme (main() et autres fonctions)
* **Contenu** : Instructions machine du programme
* **Quand** : Exécutée après `.init`, contient le point d'entrée main()
* **Appelée par** : Le runtime après l'initialisation

#### <mark style="color:green;">`.fini`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 13) -</mark> <mark style="color:green;"></mark><mark style="color:green;">**DERNIÈRE À S'EXÉCUTER**</mark>

* **Rôle** : Code de finalisation après main()
* **Contenu** : Nettoyage et destructeurs
* **Quand** : Exécutée automatiquement après la fin de main()
* **Appelée par** : Le runtime C lors de la terminaison

***

### <mark style="color:blue;">4. Sections de données</mark>

#### <mark style="color:green;">`.rodata`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 14)</mark>

* **Rôle** : Données en lecture seule (constantes, chaînes littérales)
* **Contenu** : `const char* msg = "Hello";` par exemple
* **Quand** : Accessible pendant toute l'exécution

#### <mark style="color:green;">`.eh_frame_hdr`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 15) et</mark> <mark style="color:green;"></mark><mark style="color:green;">`.eh_frame`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 16)</mark>

* **Rôle** : Informations pour la gestion des exceptions
* **Contenu** : Tables de dépilage de pile pour exceptions C++
* **Quand** : Utilisées lors du lancement d'exceptions

#### <mark style="color:green;">`.gcc_except_table`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 17)</mark>

* **Rôle** : Table des exceptions GCC
* **Contenu** : Informations sur les blocs try/catch
* **Quand** : Consultée lors de la propagation d'exceptions

***

### <mark style="color:blue;">5. Sections d'initialisation des données</mark>

#### <mark style="color:green;">`.init_array`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 18)</mark>

* **Rôle** : Tableau de pointeurs vers les constructeurs
* **Contenu** : Adresses des fonctions à appeler avant main()
* **Quand** : Parcourue par `.init` pour appeler les constructeurs

#### <mark style="color:green;">`.fini_array`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 19)</mark>

* **Rôle** : Tableau de pointeurs vers les destructeurs
* **Contenu** : Adresses des fonctions à appeler après main()
* **Quand** : Parcourue par `.fini` pour appeler les destructeurs

#### <mark style="color:green;">`.jcr`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 20)</mark>

* **Rôle** : Java Class Registration (pour compatibilité GCJ)
* **Contenu** : Informations pour l'intégration Java (souvent vide)

***

### <mark style="color:blue;">6. Sections de liaison dynamique runtime</mark>

#### <mark style="color:green;">`.dynamic`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 21)</mark>

* **Rôle** : Informations pour le loader dynamique
* **Contenu** : Références vers autres sections, bibliothèques requises
* **Quand** : Consultée par le loader au démarrage

#### <mark style="color:green;">`.got`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 22) et</mark> <mark style="color:green;"></mark><mark style="color:green;">`.got.plt`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 23)</mark>

* **Rôle** : Global Offset Table - adresses des variables/fonctions globales
* **Contenu** : Pointeurs vers les vraies adresses des symboles
* **Quand** : Remplies par le loader, utilisées pendant l'exécution

***

### <mark style="color:blue;">7. Sections de données runtime</mark>

#### <mark style="color:green;">`.data`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 24)</mark>

* **Rôle** : Données globales initialisées
* **Contenu** : Variables globales avec valeur initiale
* **Quand** : Copiées du fichier vers la mémoire au chargement

#### <mark style="color:green;">`.bss`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 25)</mark>

* **Rôle** : Données globales non initialisées
* **Contenu** : Variables globales sans valeur initiale (mises à zéro)
* **Quand** : Allouées et initialisées à zéro au chargement

#### <mark style="color:green;">`.comment`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Section 26)</mark>

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
