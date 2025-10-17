# Formats PE et COFF

## <mark style="color:red;">Formats PE et COFF (Portable Executable et Common Object File Format)</mark>

Le format **PE (Portable Executable)** est le format de fichier exécutable utilisé sous Windows (EXE, DLL, SYS, etc.),&#x20;

**COFF (Common Object File Format)** est le format de fichier objet (généralement .obj ou .lib).&#x20;

La spécification définit la structure de ces fichiers afin de faciliter le développement d’outils Windows. Le terme “Portable” rappelle que le format n’est pas lié à une architecture précise.&#x20;

Un fichier PE/COFF contient plusieurs en-têtes et sections décrivant comment le code et les données sont organisés.

* **Fichier .obj (COFF)** = pièces détachées dans l’atelier.
  * Ce sont des **morceaux de code** (fonctions) compilés séparément.
  * Ils contiennent des **références non résolues** (par ex. « cette pièce a besoin d’un boulon appelé X »).
  * Usage : **donner au linker** pour assembler.
* **Fichier .exe / .dll (PE)** = la voiture finie prête à rouler.
  * Le linker a **assemblé** toutes les pièces `.obj`, a **résolu** les références (trouvé les boulons), a ajouté de l’info pour le garage (le système Windows) pour savoir comment démarrer et charger la voiture.
  * Contient des tables comme : qui importe quelles fonctions d’autres DLL, où commence l’exécution, etc.

<mark style="color:green;">En une phrase</mark>

* **COFF (.obj)** = format pour les **pièces** (travail du compilateur).
* **PE (.exe/.dll)** = format pour la **voiture finie** (sortie du linker, utilisée par Windows).

***

### <mark style="color:blue;">1. Définition des formats PE et COFF</mark>

* **PE (Portable Executable)** : format d’**image exécutable** Windows. Utilisé pour les applications (EXE), bibliothèques dynamiques (DLL), pilotes (SYS), etc. C’est un format dit « image » car le binaire est chargé en mémoire comme une image continue. Le nom « Portable Executable » souligne l’indépendance d’architecture (le même format gère x86, x64, ARM, etc.).
* **COFF (Common Object File Format)** : format d’**objet** produit par les compilateurs/assembleurs. Un fichier .obj (ou .lib) contient des sections de code/données, des symboles et des informations de relocation. Il sert d’entrée au _linker_ (éditeur de liens) pour construire l’image finale. Ce n’est pas nécessairement lié à la programmation orientée objet.

**Tableau 1 – Concepts clés** (issus de la spécification):

<table data-full-width="true"><thead><tr><th>Concept</th><th>Définition</th></tr></thead><tbody><tr><td><strong>RVA</strong></td><td>Relative Virtual Address. Adresse d’un élément après chargement en mémoire, relative à la base d’image. En pratique l’adresse virtuelle moins l’adresse de base. Diffère généralement de l’offset sur disque.</td></tr><tr><td><strong>VA</strong></td><td>Virtual Address. Adresse virtuelle réelle (RVA + base d’image). C’est l’adresse utilisée en mémoire.</td></tr><tr><td><strong>Section</strong></td><td>Unité de code ou de données du fichier. Ex : <code>.text</code> (code), <code>.data</code> (données initialisées), etc. Tout le contenu d’une section est contigu en mémoire.</td></tr><tr><td><strong>Objet (file)</strong></td><td>Fichier .obj donné en entrée au linker. Le linker lie plusieurs objets pour produire l’image PE finale.</td></tr></tbody></table>

***

### <mark style="color:blue;">2. Structure générale d’un fichier PE</mark>

Un fichier PE comprend plusieurs zones consécutives sur le disque (figure 1) :

* **MS-DOS Stub** (image seulement) : petit exécutable DOS en début de fichier. Par défaut il affiche “This program cannot be run in DOS mode” si on lance le binaire dans DOS. Il se termine par l’offset vers le en-tête PE à l’offset 0x3C.
* **Signature PE** : 4 octets “PE\0\0” marquant le début du format PE.
* **En-tête COFF (File Header)** : en-tête principal (pour objet ou image) avec des champs tels que _Machine_, _NumberOfSections_, _TimeDateStamp_, etc..
* **En-tête optionnel (Optional Header)** : nécessaire pour les images PE (mais absent ou facultatif pour les objets). Il comporte des _champs standard_ (tailles de code/données, entry point…) et des _champs Windows spécifiques_ (ImageBase, alignements, versions, taille totale, etc.), ainsi qu’une table de **Data Directories** pointant vers des tables importantes (imports, exports, ressources…).
* **Table des sections** : liste des en-têtes de section (une entrée par section), qui décrit le nom, la taille et l’emplacement des données dans chaque section.
* **Sections de données** : zones de code ou données réelles (.text, .data, .rdata, .rsrc, etc.), alignées selon _FileAlignment_ et _SectionAlignment_. Par exemple, les sections contiennent le code exécutable, les chaînes de caractères, les tables d’import/export, les ressources, les relocations, etc. Les sections peuvent avoir des flags (exécutable, lecture seule, données non-initialisées, etc.).

Dans un fichier **COFF objet** (.obj), on trouve au lieu du DOS Stub et signature un en-tête COFF suivi directement de la table des sections. Les fichiers objets contiennent _COFF Symbol Table_ et _COFF Relocations_ (pour le linker) que l’on retrouve après les données de section.

> **Figure 1 (exemple)** – Répartition typique d’un fichier PE :\
> MS-DOS Header + Stub → Signature “PE\0\0” → En-tête COFF → En-tête optionnel → Table des sections → Données de sections (code, données, ressources, tables d’import/export, etc.).

```
[ MS-DOS Stub ]
        ↓
[ Signature "PE\0\0" ]
        ↓
[ En-tête COFF (machine, sections...) ]
        ↓
[ En-tête optionnel (entry point, image base, tailles...) ]
        ↓
[ Table des sections (descriptif de .text, .data, etc.) ]
        ↓
[ Sections (code, données, imports, exports, ressources...) ]

```

***

### <mark style="color:blue;">3. En-tête COFF (File Header)</mark>

Juste après la signature PE (ou au début pour un .obj) se trouve l’**en-tête COFF**. Il fait 20 octets et comprend :

* **Machine** (2 octets) : identifie l’architecture cible (processeur). Par exemple, 0x14c = Intel i386, 0x8664 = AMD64, 0x1c0 = ARM, 0xaa64 = ARM64, etc.. On ne peut exécuter l’image que sur une machine compatible ou émulant ce type. Par exemple :
  * IMAGE\_FILE\_MACHINE\_I386 (0x14c) : Intel 386 ou ultérieur (32‑bits).
  * IMAGE\_FILE\_MACHINE\_AMD64 (0x8664) : x64 (Intel/AMD 64 bits).
  * IMAGE\_FILE\_MACHINE\_ARM (0x1c0) et ARM64 (0xaa64) pour ARM.
* **NumberOfSections** (2 octets) : nombre de sections définies dans la table des sections, après les headers.
* **TimeDateStamp** (4 octets) : timestamp UNIX (sec depuis 1/1/1970) indiquant la date de création du fichier.
* **PointerToSymbolTable** (4 octets) : offset dans le fichier vers la table des symboles COFF (pour un .obj) ou 0 si pas de symboles. En image PE, ce champ vaut zéro (les symboles COFF sont dépréciés).
* **NumberOfSymbols** (4 octets) : nombre d’entrées dans la table de symboles. Permet de localiser la table de chaînes après. Vaut 0 pour les images PE.
* **SizeOfOptionalHeader** (2 octets) : taille en octets de l’en-tête optionnel. Non nul pour PE (fixe selon PE32 ou PE32+), mais 0 pour les objets. Sert à calculer où commence la table des sections.
* **Characteristics** (2 octets) : drapeaux décrivant les attributs du fichier. Quelques flags importants :
  * `IMAGE_FILE_EXECUTABLE_IMAGE (0x0002)` : indique que c’est une image exécutable valide. S’il n’est pas mis, le linker signale une erreur.
  * `IMAGE_FILE_DLL (0x2000)` : le fichier est une DLL.
  * `IMAGE_FILE_RELOCS_STRIPPED (0x0001)` : pas de relocations embarquées – doit être chargé à l’adresse de base préférée, sinon échec.
  * `IMAGE_FILE_LARGE_ADDRESS_AWARE (0x0020)` : l’application peut gérer des adresses >2 GB (utile en 32 bits).

> Les valeurs Machine et Characteristics sont définies par des constantes (par ex. `IMAGE_FILE_MACHINE_I386 = 0x14c`, `IMAGE_FILE_DLL = 0x2000`) que l’on retrouve dans les en-têtes d’inclusion Windows (WinNT.h).

***

### <mark style="color:blue;">4. En-tête optionnel (Optional Header)</mark>

L’**en-tête optionnel** (présent dans les images PE) contient les informations essentielles pour le loader. Il est divisé en deux parties : **champs standard** (COFF) et **champs Windows** (spécifiques à PE). Sa taille est indiquée dans SizeOfOptionalHeader du header COFF.

#### <mark style="color:green;">4.1. Champs standard (COFF)</mark>

Les premiers champs (8 champs) sont les mêmes pour tous les COFF, PE ou non :

* **Magic** (2 o) : détermine le format :
  * 0x10B = PE32 (32 bits).
  * 0x20B = PE32+ (64 bits).
  * 0x107 = ROM image (rare).\
    Ainsi, un exécutable 64 bits a Magic = 0x20B (PE32+), permettant un espace d’adressage 64 bits (bien qu’il limite la taille de l’image à 2 GB).
* **MajorLinkerVersion**, **MinorLinkerVersion** (1 o chacun) : version majeure/minor du linker utilisé.
* **SizeOfCode** (4 o) : taille totale (en octets) du code exécutable (.text) dans le fichier.
* **SizeOfInitializedData** (4 o) : taille totale des données initialisées (.data, .rdata, etc.).
* **SizeOfUninitializedData** (4 o) : taille des données non initialisées (.bss).
* **AddressOfEntryPoint** (4 o) : RVA du point d’entrée (l’adresse de départ du programme) relatif à l’image base. Pour un EXE c’est la première instruction exécutée, pour un driver c’est la fonction d’initialisation. Pour une DLL, ce champ peut être 0 si pas de _DllMain_.
* **BaseOfCode** (4 o) : RVA du début de la section contenant le code (généralement .text).
* **BaseOfData** (4 o) – _PE32 seulement_ (absent en PE32+) : RVA du début de la section de données initialisées (généralement .data). Ce champ n’existe pas en 64 bits (PE32+).

Ces champs standard donnent les tailles et adresses de base des sections principales.

#### <mark style="color:green;">4.2. Champs Windows (PE32/PE32+)</mark>

Les champs suivants (21 champs) sont spécifiques à Windows :

* **ImageBase** (4 o en PE32, 8 o en PE32+) : adresse de base préférée de chargement (généralement alignée sur 64K). Par défaut 0x00400000 pour les programmes Win32, 0x10000000 pour les DLL.
* **SectionAlignment** (4 o) : alignement (en mémoire) des sections lors du chargement. Doit être ≥ FileAlignment. Généralement égal à la taille de page (0x1000 pour x86).
* **FileAlignment** (4 o) : alignement (sur disque) des données de section. Doit être une puissance de 2 entre 512 et 64 K (0x200 à 0x10000). Par défaut 512 (0x200). Si SectionAlignment < taille page, FileAlignment == SectionAlignment.
* **MajorOperatingSystemVersion**, **MinorOperatingSystemVersion** (2 o chacun) : version minimale du système d’exploitation requise (utile pour compatibilité).
* **MajorImageVersion**, **MinorImageVersion** (2 o) : version de l’image (souvent 0).
* **MajorSubsystemVersion**, **MinorSubsystemVersion** (2 o) : version du sous-système requis.
* **Win32VersionValue** (4 o) : réservé (doit être 0).
* **SizeOfImage** (4 o) : taille totale de l’image en mémoire (headers + sections), arrondie à SectionAlignment.
* **SizeOfHeaders** (4 o) : taille combinée du stub DOS, des en-têtes PE et table des sections, arrondie à FileAlignment.
* **CheckSum** (4 o) : somme de contrôle du fichier. Vérifiée pour les drivers ou DLL critiques au chargement.
* **Subsystem** (2 o) : sous-système requis pour exécuter l’image (par ex. GUI, console, driver, EFI, etc.). Valeurs communes : 2=Windows GUI, 3=Windows CUI, 1=natif, 10/11/12=EFI, etc.
* **DllCharacteristics** (2 o) : flags de sécurité ou de configuration DLL. Les plus importants :
  * `0x0040 (DYNAMIC_BASE)` : supporte ASLR – image peut être re-localisée aléatoirement au chargement.
  * `0x0080 (FORCE_INTEGRITY)` : renforce la vérification de l’intégrité (Authenticode) lors du chargement.
  * `0x0100 (NX_COMPAT)` : compatible NX (DEP), les pages non-exécutables sont protégées.
  * `0x0400 (NO_SEH)` : pas d’exceptions structurées (SafeSEH) – le code ne doit pas utiliser SEH classique.
  * `0x0800 (NO_BIND)`, `0x2000 (WDM_DRIVER)`, etc. Voir table.
* **SizeOfStackReserve**, **SizeOfStackCommit** (4 o / 8 o) : taille de la pile réservée et engagée. Seuls _SizeOfStackCommit_ octets sont physiquement engagés au démarrage, le reste est engagé au besoin.
* **SizeOfHeapReserve**, **SizeOfHeapCommit** (4 o / 8 o) : idem pour le tas (heap) local.
* **LoaderFlags** (4 o) : réservé, doit être 0.
* **NumberOfRvaAndSizes** (4 o) : nombre d’entrées dans la table des Data Directories qui suit (typiquement 16).

#### <mark style="color:green;">4.3. Data Directories</mark>

Après les champs ci-dessus suivent les **Data Directories** : chaque répertoire est une paire (RVA, taille) pointant vers une structure importante dans l’image (ou offset fichier pour les certificates). Le champ _NumberOfRvaAndSizes_ indique combien d’entrées sont présentes. Les répertoires standard sont (indices typiques 0..15):

<table data-full-width="true"><thead><tr><th>Index</th><th>Nom</th><th>Description (RVA et taille)</th></tr></thead><tbody><tr><td>0</td><td>Export Table</td><td>Table d’exportation des fonctions (voir .edata)</td></tr><tr><td>1</td><td>Import Table</td><td>Table d’importation des DLL (voir .idata)</td></tr><tr><td>2</td><td>Resource Table</td><td>Ressources (icônes, dialogues, chaînes) (.rsrc)</td></tr><tr><td>3</td><td>Exception Table</td><td>Table des fonctions d’exceptions (section .pdata)</td></tr><tr><td>4</td><td>Certificate Table</td><td>Certificats Authenticode (accessible dans l’exe, hors mémoire)</td></tr><tr><td>5</td><td>Base Relocation Table</td><td>Base relocations (section .reloc)</td></tr><tr><td>6</td><td>Debug</td><td>Table de débogage (directory .debug, contiendra des infos PDB, etc.)</td></tr><tr><td>7</td><td>Architecture</td><td>Réservé (non utilisé, 0)</td></tr><tr><td>8</td><td>Global Ptr</td><td>RVA d’un pointeur global (pour l’IA64) (généralement 0)</td></tr><tr><td>9</td><td>TLS Table</td><td>TLS (Thread Local Storage) (section .tls)</td></tr><tr><td>10</td><td>Load Config Table</td><td>Table de configuration de chargement (LoadConfig)</td></tr><tr><td>11</td><td>Bound Import</td><td>Table d’import lié (bound)</td></tr><tr><td>12</td><td>IAT (Import Address Table)</td><td>Tableau d’adresses import (pour le binder)</td></tr><tr><td>13</td><td>Delay Import Descriptor</td><td>Descriptor des imports différés (DLL delay-load)</td></tr><tr><td>14</td><td>CLR Runtime Header</td><td>En-tête CLR (.cormeta) pour code managé/.NET</td></tr><tr><td>15</td><td>Reserved</td><td>Réservé, doit être nul</td></tr></tbody></table>

Par exemple, la Data Directory **Export** (indice 0) donne l’adresse de la _Export Directory Table_ (structure `IMAGE_EXPORT_DIRECTORY`) et sa taille. De même, l’**Import Table** (indice 1) pointe vers une liste de descripteurs (`IMAGE_IMPORT_DESCRIPTOR`) décrivant les DLL importées. Les tables _Certificate_ et _Debug_ ne sont pas chargées en mémoire (certificate donne un offset fichier).

> **Note :** il ne faut pas supposer que ces RVAs pointent au début d’une section portant un nom spécifique. Il faut plutôt parcourir la table des sections pour localiser l’adresse relative donnée.

***

### <mark style="color:blue;">5. Table des sections (Section Table)</mark>

Juste après l’en-tête (COFF + Optional) se trouve la **table des sections**. Le nombre d’entrées vaut _NumberOfSections_ du header COFF. Chaque en-tête de section occupe 40 octets et décrit la section correspondante. Un champ clé est _VirtualAddress_ (RVA) : les sections en mémoire sont triées par ordre croissant de RVA et alignées sur _SectionAlignment_.

Chaque en-tête de section comporte (voir tableau ci-dessous):

<table data-full-width="true"><thead><tr><th>Offset (dans header)</th><th>Taille</th><th>Champ</th><th>Description</th></tr></thead><tbody><tr><td>0</td><td>8</td><td><strong>Name</strong></td><td>Nom ASCII (UTF-8) sur 8 octets (suffixe ‘<code>$/num</code>’ possible pour objets).</td></tr><tr><td>8</td><td>4</td><td><strong>VirtualSize</strong></td><td>Taille en mémoire de la section (remplie de zéros si > SizeOfRawData). Pseudo‐<code>BSS</code> si 0..</td></tr><tr><td>12</td><td>4</td><td><strong>VirtualAddress</strong></td><td>RVA du début de la section dans l’image (addresse relative).</td></tr><tr><td>16</td><td>4</td><td><strong>SizeOfRawData</strong></td><td>Taille sur disque (en octets) des données initialisées dans la section. Doit être multiple de FileAlignment. Si &#x3C; VirtualSize, reste en mémoire mis à 0..</td></tr><tr><td>20</td><td>4</td><td><strong>PointerToRawData</strong></td><td>Offset fichier de la première page de données de la section. Multiple de FileAlignment. (0 si section non initialisée).</td></tr><tr><td>24</td><td>4</td><td><strong>PointerToRelocations</strong></td><td>Offset vers les entrées de relocation COFF pour cette section (objet seulement). 0 pour les images PE (non utilisé).</td></tr><tr><td>28</td><td>4</td><td><strong>PointerToLinenumbers</strong></td><td>Offset vers les entrées numéro de ligne (déprécié, souvent 0). 0 pour les images PE.</td></tr><tr><td>32</td><td>2</td><td><strong>NumberOfRelocations</strong></td><td>Nombre d’entrées de relocation pour la section (objet). 0 pour les images PE.</td></tr><tr><td>34</td><td>2</td><td><strong>NumberOfLinenumbers</strong></td><td>Nombre d’entrées ligne (déprécié, 0 dans PE).</td></tr><tr><td>36</td><td>4</td><td><strong>Characteristics</strong></td><td>Attributs de la section (drapeaux) (voir §5.1 ci-dessous).</td></tr></tbody></table>

En pratique, on reconnaît souvent les sections par leur nom (par exemple `.text` pour le code exécutable, `.data` pour les données initialisées, `.rdata` pour les données en lecture seule, `.rsrc` pour les ressources).

***

### <mark style="color:green;">5.1. Drapeaux de section (Section Flags)</mark>

Le champ **Characteristics** de chaque section est une combinaison de flags qui décrivent le contenu de la section. Voici les flags courants :

* **IMAGE\_SCN\_CNT\_CODE (0x00000020)** : section contenant du code exécutable.
* **IMAGE\_SCN\_CNT\_INITIALIZED\_DATA (0x00000040)** : section de données initialisées.
* **IMAGE\_SCN\_CNT\_UNINITIALIZED\_DATA (0x00000080)** : section de données non initialisées (BSS).
* **IMAGE\_SCN\_LNK\_INFO (0x00000200)** : section d’information (ex. `.drectve`).
* **IMAGE\_SCN\_LNK\_REMOVE (0x00000800)** : section à exclure de l’image finale (objet only).
* **IMAGE\_SCN\_LNK\_COMDAT (0x00001000)** : section COMDAT (données partagées).
* **IMAGE\_SCN\_MEM\_EXECUTE (0x20000000)** : section exécutable (peut être exécutée).
* **IMAGE\_SCN\_MEM\_READ (0x40000000)** : section lisible en mémoire.
* **IMAGE\_SCN\_MEM\_WRITE (0x80000000)** : section modifiable en mémoire.
* **IMAGE\_SCN\_MEM\_DISCARDABLE (0x02000000)** : la section peut être jetée après chargement (par ex. sections d’annotation).
* **Alignements (OBJ only)** : flags `IMAGE_SCN_ALIGN_*` (0x00100000, 0x00200000, …) spécifient l’alignement (1,2,4…8192 bytes) pour les fichiers objets.

> Par exemple, une section `.text` aura typiquement les flags `CNT_CODE | MEM_EXECUTE | MEM_READ` (code exécutable, accessible en lecture), alors qu’une section `.data` serait `CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE`.

***

### <mark style="color:blue;">6. Gestion des imports et exports</mark>

#### <mark style="color:green;">6.1. Table des exports (.edata)</mark>

La section **.edata** contient les informations d’export du module (fonctions/données que la DLL ou l’EXE rend disponibles). Elle est décrite par l’**Export Directory Table** (`IMAGE_EXPORT_DIRECTORY`) et plusieurs tables associées :

* **Export Directory** : structure contenant entre autres le RVA des tables d’adresses et de noms d’export.
* **Export Address Table** : liste des RVAs des fonctions exportées.
* **Export Name Pointer Table** : RVAs des noms des fonctions exportées.
* **Export Ordinal Table** : indices (ordinals) correspondant aux entrées des tables de noms/adresses.
* **Export Name Table** : chaînes de caractères des noms des fonctions exportées.

En clair, pour chaque export, l’image contient le nom et l’ordinal, et pointe vers son adresse en mémoire. L’importeur (ou loader) utilise cette table pour résoudre les exports.

#### <mark style="color:green;">6.2. Table des imports (.idata)</mark>

La section **.idata** gère les imports (fonctions appelées dans des DLL externes). Elle comprend :

* **Import Directory Table** : une entrée (`IMAGE_IMPORT_DESCRIPTOR`) par DLL importée. Chaque entrée indique le nom de la DLL (RVA) et les RVAs vers les tables d’import de cette DLL.
* **Import Lookup Table (ILT)** : pour chaque import, table d’entrées (par fonction ou ordinal) pointant vers la **Hint/Name Table**.
* **Hint/Name Table** : pour chaque import, ce tableau contient un mot « hint » (indice d’optimisation) suivi du nom de la fonction (ASCII) pour la résolution par nom.
* **Import Address Table (IAT)** : table parallèle au ILT, qui est remplie à l’exécution avec les adresses réelles des fonctions importées. Au moment de chargement, le loader copie soit l’adresse par ordre (ordinal) ou via le nom (hint) dans l’IAT, permettant d’appeler directement la fonction importée.

De plus, si des imports sont retardés (« delay-load »), la section .idata contient aussi un **Delay-Load Import Directory** avec une structure similaire (section 4.8) permettant de différer la résolution jusqu’à ce que le code y accède.

#### <mark style="color:green;">6.3. Base Relocations (.reloc)</mark>

Si un exécutable n’est pas chargé à son adresse de base préférée (ImageBase), il faut appliquer des relocations : la section **.reloc** contient des _blocs de relocalisation_ (IMAGE\_BASE\_RELOCATION) listant les positions à ajuster. Chaque bloc regroupe des entrées de 16 bits (type+offset). Les types diffèrent selon l’architecture (par ex. `IMAGE_REL_BASED_HIGHLOW` pour x86, etc). Si le flag **IMAGE\_FILE\_RELOCS\_STRIPPED** est présent, `.reloc` n’existe pas et l’image ne peut être déplacée (doit charger à l’adresse voulue).

#### <mark style="color:green;">6.4. Autres tables et sections</mark>

* **Symboles et tables de chaînes COFF (.obj)** : seuls les fichiers .obj contiennent une _COFF Symbol Table_ (table de symboles, record de 18 octets chacun) et une _string table_ de tous les noms longs. Un enregistrement de symbole standard contient le nom (8 octets ou offset), une valeur (adresse relative), le numéro de section (ou une valeur spéciale pour externe/absolu), le type (code/fonction), la classe de stockage (externe, statique, fonction, etc) et un nombre d’auxiliaires. Les symboles servent pour le linking (résolution des références entre objets) et pour communiquer des informations COMDAT au linker.
* **Lignes de code (deprecated)** : information de débogage très ancienne, généralement inutilisée. Les sections `.debug$*` (COFF debug) et le _Debug Directory_ existent pour supporter le debug moderne (par ex. entrées CodeView), mais ces détails sont hors-scope ici.
* **Ressources (.rsrc)** : contient les ressources (icônes, boîtes de dialogue, chaînes, etc.) organisées sous forme d’arbre de répertoires. La Data Directory _Resource Table_ pointe vers une _Resource Directory Table_ dans .rsrc.
* **TLS (.tls)** : Table _Thread Local Storage_ (variables par thread). L’entrée _TLS Table_ dirige vers une structure décrivant les emplacements initiaux et des callbacks TLS.
* **Load Config** : structure spéciale (Load Configuration) contenant des informations pour le loader (sécurité, exception handlers, FS/GS cookies, etc.).
* **Certificats (Authenticode)** : l’entrée _Certificate Table_ contient des certificats numériques (signature du fichier). Il n’est pas chargé en mémoire : son RVA est en fait un offset fichier vers les données du certificat. Les certificats viennent à la fin du fichier.

***

### <mark style="color:blue;">7. Formats 32 bits (PE32) vs 64 bits (PE32+)</mark>

La principale différence se situe dans _Magic_ (0x10B vs 0x20B) et la taille de certains champs. En **PE32+ (64 bits)** :

* Les champs _ImageBase_, _SizeOfStackReserve/Commit_, _SizeOfHeapReserve/Commit_ passent de 4 à 8 octets pour supporter 64 bits.
* Le champ _BaseOfData_ (présent en PE32) **n’existe pas** en PE32+.
* L’alignement par défaut et autres champs restent globalement identiques, mais tous les RVAs sont désormais 64 bits virtuels.
* PE32+ permet un espace d’adressage 64 bits (théorique), tout en limitant la taille de l’image à 2 GB.

En pratique, un OS 64 bits charge une image PE32+ pour les applications 64 bits, tandis que les programmes 32 bits restent en PE32. Des flags comme `IMAGE_FILE_32BIT_MACHINE` (0x0100) indiquent aussi si l’image est pour une architecture 32 bits.

***

### <mark style="color:blue;">8. Types de fichiers PE/COFF</mark>

* **EXE (Image exécutable)** : contient un en-tête PE complet (DOS stub, signature, COFF, optional header, sections). Drapeau IMAGE\_FILE\_EXECUTABLE\_IMAGE=1. Peut contenir des exports (rare, mais possible) et fréquemment des imports.
* **DLL (Dynamic Link Library)** : similaire à un EXE, mais avec IMAGE\_FILE\_DLL=1. Utilise souvent des exports (fonctions fournies par la DLL) et des imports.
* **SYS (Driver)** : format PE, souvent un driver noyau. Souvent un type de DLL. Peut avoir `IMAGE_SUBSYSTEM_NATIVE` (1) dans Subsystem car pas d’interface utilisateur.
* **OBJ (fichier objet COFF)** : pas d’en-tête DOS ni signature PE, seulement en-tête COFF et optional header (facultatif) suivi de table des sections. Contient table de relocations et symboles. Ne possède pas de Data Directories PE typiques.
* **LIB (Archive COFF)** : fichier archive (ar) qui regroupe plusieurs fichiers objets. Il contient un entête global (“!\n”), suivi d’en-têtes de membres. Les bibliothèques d’import (fichiers .lib pour DLL) ont un format particulier (stubs d’import). Ces formats sont décrits en annexe du spec.
* **EXE 16 bits, COM, NE** : anciens formats (NE, MZ) ne sont pas couverts ici.

***

### <mark style="color:blue;">9. Champs d’en-tête et signification</mark>

Pour synthèse, voici les principaux champs vus précédemment (COFF et Optional) :

* **COFF Header** (20 o) : Machine, Nombre de sections, Timestamp, pointeur/nb symboles (obj), taille optional, Flags.
* **Optional Header Standard** : Magic, linker vers, tailles (code/data), AddressOfEntryPoint, BaseOfCode, (BaseOfData).
* **Optional Header Windows** : ImageBase, SectionAlignment, FileAlignment, versions OS, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics, Stack/Heap sizes, Nombre de DataDirs.
* **Data Directories (chacun 8 o)** : liste des pointeurs (RVA+taille) vers Export, Import, Ressources, Exception, Relocations, Debug, TLS, LoadConfig, BoundImport, IAT, DelayImport, CLR, etc.
* **Section Header (40 o)** : Name\[8], VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocs, PointerToLinenos, NumberOfRelocs, NumberOfLinenos, Characteristics.

Tous ces champs ont été décrits plus haut avec leurs significations. Les champs non mentionnés ou marqués “réservé” doivent rester à 0.

***

### <mark style="color:blue;">10. Compatibilité, sécurité et alignement</mark>

* **Compatibilité** : Les champs _MajorOperatingSystemVersion_ / _MajorSubsystemVersion_ permettent de requérir une version minimale de l’OS. L’OS vérifie _CheckSum_ pour certains exécutables (drivers, DLL système critiques). Le flag `IMAGE_FILE_RELOCS_STRIPPED` interdit le chargement à une autre adresse que l’ImageBase (charger autrement = erreur).
* **Alignement** : Le loader impose que _FileAlignment_ soit ≤ _SectionAlignment_, et deux puissances de 2 appropriées. En général, _SectionAlignment_ = taille de page (alignement mémoire) et _FileAlignment_ = 0x200 (512 octets). Si _SectionAlignment_ < taille page, les données des sections doivent avoir un offset fichier égal à leur RVA (alignement identique).
* **Sécurité** : Les flags _DLL Characteristics_ contrôlent diverses protections :
  * **ASLR** : `DYNAMIC_BASE (0x40)` active l’adressage aléatoire (ASLR).
  * **DEP/NX** : `NX_COMPAT (0x100)` indique que les pages peuvent être marquées NX (Data Execution Prevention).
  * **SafeSEH** : `NO_SEH (0x0400)` indique que le binaire n’utilise pas les handlers SEH classiques, forçant l’usage des handlers connus (“safe”).
  * **Integrité du code** : `FORCE_INTEGRITY (0x80)` impose une vérification de signature Authenticode.
* **Limitations** : Windows limite à 96 le nombre de sections. Certaines combinaisons de flags (comme PAR, OHDR) sont ignorées ou réservées. Le champ _Characteristics_ de l’objet détermine aussi s’il s’agit d’un fichier système (`IMAGE_FILE_SYSTEM` 0x1000), destinés multitraitement (`IMAGE_FILE_UP_SYSTEM_ONLY` 0x4000), etc.

> **Tableau 2 – Flags de sécurité (DLL Characteristics)** (extrait) :

| Flag (hex) | Nom                     | Signification                             |
| ---------- | ----------------------- | ----------------------------------------- |
| 0x0040     | DYNAMIC\_BASE           | Peut être re-localisée (ASLR)             |
| 0x0080     | FORCE\_INTEGRITY        | Code Integrity (Authenticode) vérifié     |
| 0x0100     | NX\_COMPAT              | Compatible NX/DEP (pages non-exécutables) |
| 0x0200     | NO\_ISOLATION           | (obsolete)                                |
| 0x0400     | NO\_SEH                 | N’utilise pas le SEH structuré (SafeSEH)  |
| 0x0800     | NO\_BIND                | Ne lie pas l’image (OBSOLETE)             |
| 0x2000     | WDM\_DRIVER             | Driver WDM                                |
| 0x8000     | TERMINAL\_SERVER\_AWARE | Conscient Terminal Server                 |

***
