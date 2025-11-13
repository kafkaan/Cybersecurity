# APK Android

***

### <mark style="color:red;">1. Introduction aux APK</mark>

#### <mark style="color:green;">Qu'est-ce qu'un APK ?</mark>

Un **APK (Android Package)** est le format de fichier utilisé par Android pour distribuer et installer des applications mobiles. C'est essentiellement un **conteneur ZIP** qui regroupe tous les éléments nécessaires au fonctionnement de votre application.

**Analogie simple :** Imaginez un APK comme une valise pour voyager. Tout comme une valise contient vos vêtements, documents et objets personnels organisés, un APK contient le code de votre app, les images, les sons, et toutes les ressources nécessaires, organisés de manière structurée.

***

#### <mark style="color:green;">Caractéristiques Clés</mark>

* **Format standard** pour toutes les applications Android
* **Contenu complet** : code, ressources, assets, bibliothèques natives
* **Signature numérique** obligatoire pour des raisons de sécurité
* **Distribution** via Google Play Store ou installation directe (sideloading)
* **Vérification d'intégrité** : Android vérifie que l'APK n'a pas été modifié

***

#### <mark style="color:green;">Pourquoi la signature est-elle importante ?</mark>

La signature numérique garantit :

* **L'authenticité** : L'app provient bien du développeur légitime
* **L'intégrité** : L'APK n'a pas été modifié après sa création
* **Les mises à jour** : Seul le propriétaire de la clé peut mettre à jour l'app

***

### <mark style="color:red;">2. Structure Détaillée d'un APK</mark>

Un APK est organisé comme une archive ZIP avec une structure bien définie. Voici chaque composant en détail :

#### <mark style="color:green;">📁 META-INF/ - Le Coffre-Fort de Sécurité</mark>

Ce dossier contient les informations de signature qui garantissent l'authenticité de votre application.

**Fichiers principaux :**

* **MANIFEST.MF** : Liste tous les fichiers de l'APK avec leurs signatures (hash SHA-1)
  * Pensez-y comme un "inventaire signé" de tout ce qui est dans l'APK
  * Chaque fichier a une empreinte digitale unique
* **CERT.RSA** ou **CERT.DSA** : Le certificat du développeur
  * C'est la "carte d'identité" de l'application
  * Contient la clé publique utilisée pour vérifier la signature
* **CERT.SF** : Liste des ressources avec leurs digests SHA-1
  * C'est une couche de sécurité supplémentaire
  * Signe le fichier MANIFEST.MF lui-même

**Exemple concret :**

```
META-INF/
├── MANIFEST.MF    (Liste : icon.png, SHA1: abc123...)
├── CERT.RSA       (Certificat du développeur)
└── CERT.SF        (Signature du manifest)
```

#### <mark style="color:green;">📁 lib/ - Les Bibliothèques Natives</mark>

Contient les bibliothèques compilées en **code natif** (C/C++) pour des performances maximales.

**Organisation par architecture CPU :**

```
lib/
├── armeabi-v7a/    (ARM 32-bit - anciens téléphones)
├── arm64-v8a/      (ARM 64-bit - téléphones modernes)
├── x86/            (Intel 32-bit - émulateurs)
└── x86_64/         (Intel 64-bit - chromebooks)
```

**Pourquoi plusieurs architectures ?**

Les processeurs de téléphones ne parlent pas tous le même "langage machine". Un Samsung Galaxy utilise généralement ARM, tandis qu'un émulateur sur votre PC utilise x86. Le système Android choisit automatiquement la bonne bibliothèque selon le processeur du téléphone.

**Exemple de fichiers .so (Shared Object) :**

* `libnative-lib.so` : Votre code C/C++ personnalisé
* `libopencv.so` : Bibliothèque de vision par ordinateur
* `libunity.so` : Moteur de jeu Unity

**💡 Astuce d'optimisation :** Si vous ciblez uniquement les téléphones modernes, vous pouvez ne garder que `arm64-v8a`, réduisant considérablement la taille de votre APK.

#### <mark style="color:green;">📁 res/ - Les Ressources de l'Application</mark>

Ce dossier contient toutes les ressources **compilées** de votre application. Android les compile pour optimiser les performances.

**Structure organisée par type :**

```
res/
├── drawable/           (Images génériques)
├── drawable-hdpi/      (Haute densité - 240 dpi)
├── drawable-xhdpi/     (Extra haute - 320 dpi)
├── drawable-xxhdpi/    (2x extra haute - 480 dpi)
├── drawable-xxxhdpi/   (3x extra haute - 640 dpi)
├── layout/             (Interfaces XML)
├── layout-land/        (Layouts en mode paysage)
├── values/             (Strings, couleurs, dimensions)
├── values-fr/          (Traductions françaises)
├── values-es/          (Traductions espagnoles)
├── raw/                (Fichiers bruts non compilés)
└── xml/                (Fichiers XML divers)
```

**Comprendre les densités d'écran :**

Android choisit automatiquement la bonne image selon la densité de l'écran :

* **mdpi** (160 dpi) : 1x - écrans basiques
* **hdpi** (240 dpi) : 1.5x - écrans moyens
* **xhdpi** (320 dpi) : 2x - écrans HD
* **xxhdpi** (480 dpi) : 3x - écrans Full HD
* **xxxhdpi** (640 dpi) : 4x - écrans 4K

**Exemple pratique :** Si votre icône fait 48x48 pixels en mdpi, elle devra faire :

* 72x72 en hdpi
* 96x96 en xhdpi
* 144x144 en xxhdpi
* 192x192 en xxxhdpi

**Fichiers de ressources :**

* `strings.xml` : Tous les textes de l'app (pour la traduction)
* `colors.xml` : Palette de couleurs
* `dimens.xml` : Dimensions (marges, tailles de texte)
* `styles.xml` : Styles réutilisables

#### <mark style="color:green;">📁 assets/ - Les Fichiers Bruts</mark>

Contrairement à `res/`, les fichiers dans `assets/` **ne sont pas compilés** et gardent leur format original. Ils sont accessibles via `AssetManager`.

**Cas d'usage typiques :**

```
assets/
├── fonts/
│   ├── Roboto-Regular.ttf
│   └── Roboto-Bold.ttf
├── data/
│   ├── levels.json        (Données de jeu)
│   └── config.json        (Configuration)
├── sounds/
│   └── background.mp3
└── html/
    └── help.html          (Page d'aide locale)
```

**Différence assets/ vs res/ :**

| assets/                        | res/                                     |
| ------------------------------ | ---------------------------------------- |
| Fichiers bruts                 | Fichiers compilés                        |
| Accès par chemin de fichier    | Accès par ID de ressource                |
| Pas de variantes automatiques  | Variantes automatiques (densité, langue) |
| Utilisé pour données complexes | Utilisé pour UI et ressources standards  |

**Exemple de code pour lire un asset :**

```java
AssetManager assetManager = getAssets();
InputStream inputStream = assetManager.open("data/config.json");
```

#### <mark style="color:green;">📄 AndroidManifest.xml - Le Fichier de Configuration</mark>

C'est le **cerveau** de votre application. Il décrit tout ce que le système Android doit savoir sur votre app.

**Informations contenues (en XML binaire pour l'APK) :**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.monapp"
    android:versionCode="1"
    android:versionName="1.0">

    <!-- Permissions -->
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    
    <!-- Fonctionnalités requises -->
    <uses-feature android:name="android.hardware.camera"/>
    
    <!-- Version SDK -->
    <uses-sdk
        android:minSdkVersion="21"
        android:targetSdkVersion="34"/>

    <application
        android:icon="@drawable/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">
        
        <!-- Activité principale -->
        <activity android:name=".MainActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        
        <!-- Services -->
        <service android:name=".MusicService"/>
        
    </application>
</manifest>
```

**Éléments clés expliqués :**

* **package** : Identifiant unique de votre app (comme une adresse postale)
* **versionCode** : Numéro de version interne (incrémenté à chaque release)
* **versionName** : Numéro visible par l'utilisateur (ex: "1.2.3")
* **permissions** : Ce que l'app peut faire (Internet, caméra, GPS, etc.)
* **uses-feature** : Hardware requis (évite l'installation sur appareils incompatibles)
* **minSdkVersion** : Version Android minimale (21 = Android 5.0 Lollipop)
* **targetSdkVersion** : Version pour laquelle l'app est optimisée

**Pourquoi le manifest est-il en format binaire dans l'APK ?**

* **Taille réduite** : Le XML binaire est plus compact
* **Parsing plus rapide** : Android le lit plus rapidement
* **Sécurité** : Plus difficile à modifier sans casser la signature

#### <mark style="color:green;">📄 classes.dex - Le Code Exécutable</mark>

C'est le **cœur de votre application** : votre code Java/Kotlin compilé en bytecode DEX (Dalvik Executable).

**Structure :**

```
classes.dex      (Code principal)
classes2.dex     (Si multidex activé)
classes3.dex     (Applications complexes)
...
```

**Pourquoi plusieurs fichiers DEX ?**

Android avait une limite de **65 536 méthodes** par fichier DEX. Les grandes applications dépassent cette limite, d'où le **multidex** (plusieurs fichiers).

**Contenu d'un fichier DEX :**

* Toutes vos classes Java/Kotlin
* Les bibliothèques externes (dependencies)
* Le bytecode optimisé pour Android

**Exemple de ce qui est dans classes.dex :**

```
MainActivity.class      → bytecode DEX
DatabaseHelper.class    → bytecode DEX
NetworkManager.class    → bytecode DEX
+ toutes les dépendances Gradle
```

**💡 Point technique :** Le format DEX est optimisé pour la mémoire limitée des appareils mobiles, contrairement au bytecode Java classique (.class) qui est conçu pour les ordinateurs.

#### <mark style="color:green;">📄 resources.arsc - La Table de Ressources</mark>

C'est un fichier binaire qui fait le **mapping** entre les IDs de ressources et leurs valeurs réelles.

**Rôle :**

Quand vous écrivez `R.string.app_name` dans votre code, Android utilise `resources.arsc` pour trouver la vraie valeur selon :

* La langue du téléphone
* La densité d'écran
* La taille d'écran
* L'orientation
* Le mode nuit/jour

**Structure interne (simplifiée) :**

```
resources.arsc
├── String Pool (tous les strings)
├── Resource IDs
│   ├── 0x7f010001 → "Hello" (en)
│   ├── 0x7f010001 → "Bonjour" (fr)
│   └── 0x7f010001 → "Hola" (es)
├── Configurations
│   ├── fr-rFR (Français France)
│   ├── en-rUS (Anglais US)
│   └── es-rES (Espagnol Espagne)
└── Type mappings
```

**Exemple pratique :**

Votre code :

```java
String appName = getString(R.string.app_name);
```

Ce qui se passe :

1. `R.string.app_name` = ID `0x7f050001`
2. Android consulte `resources.arsc`
3. Vérifie la langue système (ex: français)
4. Retourne la valeur correspondante : "Mon Application"

***

### <mark style="color:red;">3. Processus de Compilation : Du Code à l'APK</mark>

Comprendre comment votre code devient un APK est essentiel pour optimiser vos applications.

#### <mark style="color:green;">Vue d'Ensemble du Pipeline de Build</mark>

{% code fullWidth="true" %}
```
┌─────────────────┐
│  Code Source    │
│ (.java/.kt)     │
└────────┬────────┘
         ↓
┌─────────────────┐
│ Compilateur     │
│ Java/Kotlin     │
└────────┬────────┘
         ↓
┌─────────────────┐
│ Bytecode Java   │
│ (.class)        │
└────────┬────────┘
         ↓
┌─────────────────┐
│ D8 Compiler     │
│ (class → dex)   │
└────────┬────────┘
         ↓
┌─────────────────┐
│ Fichiers DEX    │
│ (.dex)          │
└────────┬────────┘
         │
         ↓
    ┌────────────────────┐
    │   APK Packager     │
    │                    │
    │ ┌────────────────┐ │
    │ │ DEX files      │ │
    │ │ Resources      │ │
    │ │ Assets         │ │
    │ │ Native libs    │ │
    │ │ Manifest       │ │
    │ └────────────────┘ │
    └─────────┬──────────┘
              ↓
    ┌─────────────────┐
    │  APK Signer     │
    │  (jarsigner)    │
    └─────────┬───────┘
              ↓
    ┌─────────────────┐
    │  zipalign       │
    │  (optimisation) │
    └─────────┬───────┘
              ↓
    ┌─────────────────┐
    │  APK Final      │
    │  (prêt)         │
    └─────────────────┘
```
{% endcode %}

#### <mark style="color:green;">Étape 1 : Compilation du Code Source</mark>

**1.1 Compilation Java/Kotlin → Bytecode**

```
MainActivity.java
UserProfile.kt
NetworkHelper.java
         ↓
   javac / kotlinc
         ↓
MainActivity.class
UserProfile.class
NetworkHelper.class
```

À ce stade, vous avez des fichiers `.class` standard Java, **pas encore** compatibles avec Android.

**1.2 Transformation en DEX avec D8**

**D8** est le compilateur moderne d'Android qui convertit le bytecode Java en bytecode DEX (Dalvik Executable).

**Pourquoi DEX plutôt que .class ?**

| Java Bytecode (.class)      | DEX Bytecode (.dex)                  |
| --------------------------- | ------------------------------------ |
| Basé sur une pile (stack)   | Basé sur des registres               |
| Un fichier par classe       | Toutes les classes dans 1-N fichiers |
| Optimisé pour desktop       | Optimisé pour mobile                 |
| Consommation mémoire élevée | Consommation mémoire réduite         |

**Avantages de DEX :**

* **Taille réduite** : Partage des constantes communes entre classes
* **Performance** : Architecture à registres plus rapide sur ARM
* **Optimisé mobile** : Conçu pour mémoire et batterie limitées

**Exemple de réduction :**

```
Fichiers .class : 2.5 MB (100 fichiers)
        ↓
     D8 compile
        ↓
Fichiers .dex : 1.8 MB (1-3 fichiers)
```

#### <mark style="color:green;">Étape 2 : Traitement des Ressources avec AAPT2</mark>

**AAPT2 (Android Asset Packaging Tool 2)** compile et package toutes vos ressources.

**Pipeline de ressources :**

```
Ressources brutes
├── res/
│   ├── layout/activity_main.xml
│   ├── drawable/icon.png
│   └── values/strings.xml
└── AndroidManifest.xml
         ↓
    AAPT2 Compile
         ↓
Ressources compilées
├── layout/activity_main.xml (binaire)
├── drawable/icon.png (optimisé)
└── resources.arsc (table de mapping)
         ↓
    AAPT2 Link
         ↓
Package de ressources final
```

**Ce que fait AAPT2 :**

1. **Compile les XML en binaire** : Plus compact et plus rapide à parser
2. **Génère les IDs de ressources** : Crée le fichier `R.java` avec tous les IDs
3. **Optimise les images** : PNG crushing automatique
4. **Crée resources.arsc** : Table de mapping des ressources
5. **Vérifie les références** : S'assure que toutes les ressources référencées existent

**Exemple de R.java généré :**

```java
public final class R {
    public static final class string {
        public static final int app_name = 0x7f050001;
        public static final int hello = 0x7f050002;
    }
    public static final class layout {
        public static final int activity_main = 0x7f030001;
    }
    public static final class drawable {
        public static final int icon = 0x7f020001;
    }
}
```

#### <mark style="color:green;">Étape 3 : Optimisation avec R8</mark>

**R8** est l'outil moderne qui remplace ProGuard. Il fait 3 choses cruciales :

**3.1 Shrinking (Réduction)**

Supprime le code et les ressources **jamais utilisés**.

```java
// Avant R8
public class Utils {
    public void usedMethod() { ... }      // ✅ Gardé
    public void unusedMethod() { ... }    // ❌ Supprimé
}

// Après R8
public class Utils {
    public void usedMethod() { ... }      // Seul le code utilisé reste
}
```

**Impact :** Réduction de 30-50% de la taille du code typiquement.

**3.2 Obfuscation (Obscurcissement)**

Renomme les classes, méthodes et champs pour rendre le reverse engineering difficile.

```java
// Avant obfuscation
public class UserManager {
    private String userName;
    public void authenticateUser() { ... }
}

// Après obfuscation
public class a {
    private String b;
    public void c() { ... }
}
```

**Pourquoi c'est important ?**

* Protège votre code des hackers
* Réduit encore la taille (noms plus courts)
* Complique le vol de propriété intellectuelle

**3.3 Optimization (Optimisation)**

Optimise le bytecode pour de meilleures performances :

* Inline des petites méthodes
* Supprime les instructions mortes
* Optimise les boucles
* Simplifie les conditions

**Exemple :**

```java
// Avant
if (DEBUG && VERBOSE) {
    log("Message");
}

// Après (si DEBUG = false)
// Code complètement supprimé car jamais exécuté
```

**Configuration R8 (proguard-rules.pro) :**

```proguard
# Garde les classes annotées avec @Keep
-keep @androidx.annotation.Keep class *

# Garde les modèles de données
-keep class com.example.models.** { *; }

# Garde les méthodes natives
-keepclasseswithmembernames class * {
    native <methods>;
}

# Désactive l'obfuscation pour le debug
-dontobfuscate
```

#### <mark style="color:green;">Étape 4 : Assemblage de l'APK</mark>

Le **APK Packager** combine tous les éléments :

```
Composants                    APK Final
├── classes.dex         →    ├── classes.dex
├── classes2.dex        →    ├── classes2.dex
├── resources.arsc      →    ├── resources.arsc
├── AndroidManifest.xml →    ├── AndroidManifest.xml
├── res/                →    ├── res/
├── assets/             →    ├── assets/
└── lib/                →    ├── lib/
                             └── META-INF/
```

**Format de sortie :** Un fichier ZIP avec extension `.apk`

#### <mark style="color:green;">Étape 5 : Signature de l'APK</mark>

**Pourquoi signer ?**

Android **refuse d'installer** un APK non signé. La signature garantit :

* L'authenticité du développeur
* L'intégrité de l'APK
* La légitimité des mises à jour

**Types de signature :**

**Debug Signature (développement) :**

```
Clé : Générée automatiquement par Android Studio
Validité : 1 an
Usage : Tests et développement uniquement
```

**Release Signature (production) :**

```
Clé : Créée par vous et gardée secrète
Validité : 25 ans minimum
Usage : Publication sur Play Store
⚠️ CRITIQUE : Ne perdez JAMAIS cette clé !
```

**Processus de signature :**

```
APK non signé
      ↓
jarsigner (avec votre clé)
      ↓
APK signé (mais non optimisé)
      ↓
zipalign (optimisation)
      ↓
APK final prêt pour distribution
```

#### <mark style="color:green;">Étape 6 : Zipalign - Optimisation Finale</mark>

**zipalign** aligne les données non compressées sur des limites de 4 octets.

**Avantage :**

* Réduit la consommation de RAM
* Accélère l'accès aux ressources
* Améliore les performances globales

**Avant zipalign :**

```
[Header][Data1][Data2][...]  (données non alignées)
```

**Après zipalign :**

```
[Header][Padding][Data1][Padding][Data2][...]  (aligné sur 4 octets)
```

**Impact :** Économie de 10-30% de RAM lors de l'exécution.

#### <mark style="color:green;">Outils de Build Modernes</mark>

**D8** (Dex Compiler)

* Remplace dx (ancien compilateur)
* Plus rapide
* Meilleur débogage
* DEX plus petit

**R8** (Code Shrinker & Obfuscator)

* Remplace ProGuard
* Intégré à Android Gradle Plugin
* Plus rapide
* Meilleur shrinking
* Optimisations plus agressives

**Gradle Build System**

Votre fichier `build.gradle` orchestre tout :

```gradle
android {
    compileSdkVersion 34
    
    defaultConfig {
        applicationId "com.example.app"
        minSdkVersion 21
        targetSdkVersion 34
        versionCode 1
        versionName "1.0"
    }
    
    buildTypes {
        release {
            minifyEnabled true       // Active R8
            shrinkResources true     // Supprime les ressources inutilisées
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                          'proguard-rules.pro'
        }
        debug {
            minifyEnabled false      // Pas d'obfuscation en debug
        }
    }
}
```

***

### <mark style="color:red;">4. Évolution du Runtime Android : Dalvik → ART</mark>

#### <mark style="color:green;">Comprendre le Runtime</mark>

Le **runtime** est l'environnement qui exécute votre code. C'est comme un moteur qui lit et exécute les instructions de votre application.

#### <mark style="color:green;">Dalvik Virtual Machine (2008-2014)</mark>

**Architecture :**

* Machine virtuelle **basée sur des registres**
* Compilation **JIT (Just-In-Time)**
* Conçue pour des appareils avec 192 MB de RAM

**Comment fonctionne JIT ?**

```
Lancement de l'app
       ↓
Lecture du code DEX
       ↓
Interprétation ligne par ligne
       ↓
Code chaud détecté (exécuté souvent)
       ↓
Compilation JIT en code natif
       ↓
Exécution du code natif (plus rapide)
```

**Avantages de Dalvik :**

* ✅ Installation rapide (pas de compilation)
* ✅ Moins d'espace de stockage utilisé
* ✅ Mises à jour rapides

**Inconvénients :**

* ❌ Démarrage lent (compilation à chaque lancement)
* ❌ Performance variable
* ❌ Consommation batterie élevée (compilation continue)
* ❌ Utilisation CPU élevée au runtime

#### <mark style="color:green;">Android Runtime (ART) - Depuis Android 5.0</mark>

**Révolution avec AOT (Ahead-Of-Time) :**

**À l'installation :**

```
Installation APK
       ↓
Extraction DEX
       ↓
Compilation AOT complète
       ↓
Code natif généré (.oat files)
       ↓
App prête (code natif stocké)
```

**Au lancement :**

```
Lancement app
       ↓
Lecture code natif directement
       ↓
Exécution immédiate (pas de compilation)
```

**Avantages d'ART :**

* ✅ Démarrage ultra-rapide
* ✅ Performance constante et élevée
* ✅ Meilleure gestion mémoire
* ✅ Moins de consommation batterie
* ✅ Garbage Collection amélioré

**Inconvénients :**

* ❌ Installation plus longue (compilation)
* ❌ Plus d'espace de stockage (code natif)
* ❌ Mises à jour plus longues

#### <mark style="color:green;">ART Moderne (Android 7.0+) - Le Meilleur des Deux Mondes</mark>

**Système hybride JIT + AOT + Profile-Guided :**

```
Installation
       ↓
Copie du DEX (pas de compilation)
       ↓
Installation rapide ✅
       ↓
Première exécution
       ↓
Mode interprété + JIT léger
       ↓
Profiling du code
       ↓
Identification du code "chaud"
       ↓
Téléphone inactif + en charge
       ↓
Compilation AOT du code critique
       ↓
Performance optimale ✅
```

**Profile-Guided Compilation (PGC) :**

Android analyse **comment vous utilisez l'app** :

* Quelles fonctions sont appelées souvent ?
* Quels chemins d'exécution sont critiques ?
* Quel code peut rester interprété ?

Puis il compile **uniquement le code important**.

**Résultat :**

* ⚡ Installation rapide
* ⚡ Performance maximale
* 💾 Espace de stockage optimisé
* 🔋 Batterie économisée

#### <mark style="color:green;">Comparaison Détaillée</mark>

| Aspect                    | Dalvik      | ART (AOT pur) | ART Moderne (Hybride) |
| ------------------------- | ----------- | ------------- | --------------------- |
| **Installation**          | Rapide ⚡    | Lente 🐌      | Rapide ⚡              |
| **Premier lancement**     | Lent 🐌     | Rapide ⚡      | Moyen 👍              |
| **Performance stable**    | Variable 📊 | Excellente ⚡⚡ | Excellente ⚡⚡         |
| **Stockage utilisé**      | Faible 💾   | Élevé 💾💾    | Moyen 💾              |
| **Consommation batterie** | Élevée 🔋🔋 | Faible 🔋     | Faible 🔋             |
| **Gestion mémoire**       | Basique     | Excellente    | Excellente            |
| **Mises à jour**          | Rapides     | Lentes        | Rapides               |

#### <mark style="color:green;">Pourquoi le Format DEX est Toujours Utilisé ?</mark>

**Question importante :** Si ART est si différent de Dalvik, pourquoi utiliser toujours le format DEX ?

**Réponses :**

1. **Compatibilité universelle**
   * Un seul APK fonctionne sur tous les Android (5.0 à 15.0+)
   * Pas besoin de recompiler pour chaque version
2. **Séparation format/runtime**
   * Le format DEX est un **standard de distribution**
   * Le runtime (Dalvik/ART) est un **détail d'implémentation**
   * Permet l'évolution sans casser les apps existantes
3. **Écosystème et outils**
   * Tous les outils Android connaissent DEX
   * Bibliothèques, frameworks, debuggers
   * Chaîne de compilation stable
4. **Flexibilité**
   * ART peut expérimenter avec différentes stratégies de compilation
   * Sans affecter les développeurs

**Analogie :** C'est comme un DVD (format) qui peut être lu par différents lecteurs (Samsung, Sony, etc.). Le format reste le même, mais les lecteurs évoluent.

#### <mark style="color:green;">Le Garbage Collector d'ART</mark>

**Améliorations majeures :**

**Dalvik GC :**

```
Pause complète de l'app → Collecte → Reprise
(Pauses visibles = lag dans l'interface)
```

**ART GC moderne :**

```
Collection concurrente (en arrière-plan)
Pauses ultra-courtes (<5ms)
Compaction de mémoire
Générationnelle (jeunes/vieux objets)
```

**Impact pour les développeurs :**

* Moins de freezes visibles
* Interface plus fluide
* Meilleure expérience utilisateur
* Apps plus réactives

***

### <mark style="color:red;">5. Analyse d'APK avec APK Analyzer</mark>

#### <mark style="color:green;">Qu'est-ce que l'APK Analyzer ?</mark>

C'est un outil intégré à **Android Studio** qui vous permet de décortiquer un APK pour comprendre sa composition et optimiser sa taille.

#### <mark style="color:green;">Accéder à l'APK Analyzer</mark>

**3 méthodes :**

1. **Drag & Drop** : Glissez un APK dans la fenêtre d'Android Studio
2. **Via l'explorateur** : `Project` → `build/outputs/apk/` → Double-clic sur l'APK
3. **Via le menu** : `Build` → `Analyze APK` → Sélectionnez votre APK

#### Interface de l'APK Analyzer

```
┌─────────────────────────────────────────┐
│  Raw Size | Download Size | % of Total  │
├─────────────────────────────────────────┤
│  📁 classes.dex         3.2 MB    45%   │
│  📁 res/                1.8 MB    25%   │
│  📁 resources.arsc      0.8 MB    11%   │
│  📁 lib/                0.9 MB    13%   │
│  📁 assets/             0.3 MB     4%   │
│  📁 META-INF/           0.1 MB     1%   │
│  📄 AndroidManifest.xml 0.05 MB    1%   │
├─────────────────────────────────────────┤
│  Total:                 7.15 MB   100%  │
└─────────────────────────────────────────┘
```

#### <mark style="color:green;">Fonctionnalités Principales</mark>

**1. Analyse de la Taille**

**Raw Size vs Download Size :**

* **Raw Size** : Taille réelle non compressée
* **Download Size** : Taille que l'utilisateur télécharge (compressée)

**Exemple :**

```
classes.dex
- Raw Size: 3.2 MB
- Download Size: 1.1 MB (compression ~65%)

res/drawable/
- Raw Size: 2.5 MB
- Download Size: 2.4 MB (images déjà compressées)
```

**Comprendre la compression :**

Le Play Store compresse votre APK. Certains fichiers se compressent mieux :

* ✅ Très compressible : XML, code DEX, texte
* ❌ Peu compressible : Images PNG/JPG, audio MP3, vidéos

**2. Inspection du DEX**

**Visualisation du code compilé :**

```
classes.dex (3.2 MB)
├── com.example.app (450 KB)
│   ├── MainActivity (45 KB)
│   ├── UserProfile (38 KB)
│   └── DatabaseHelper (67 KB)
├── androidx.* (1.8 MB)
│   ├── appcompat (400 KB)
│   ├── recyclerview (350 KB)
│   └── lifecycle (280 KB)
├── com.google.android.gms (650 KB)
└── kotlin.* (320 KB)
```

**Analyse des méthodes :**

L'APK Analyzer vous montre :

* **Nombre total de méthodes** (limite : 65 536 par DEX)
* **Références de méthodes**
* **Champs définis**
* **Classes définies**

**Exemple de rapport :**

```
Defined Methods: 24,358 / 65,536
Referenced Methods: 31,245
Defined Fields: 12,467
Defined Classes: 3,289
```

**💡 Astuce :** Si vous approchez de 65 536 méthodes, vous devrez activer le multidex.

**3. Analyse des Ressources**

**Visualisation hiérarchique :**

```
res/
├── drawable/ (1.2 MB)
│   ├── drawable-mdpi/ (200 KB)
│   ├── drawable-hdpi/ (350 KB)
│   ├── drawable-xhdpi/ (450 KB)
│   └── drawable-xxhdpi/ (200 KB)  ⚠️ Manquant xxxhdpi?
├── layout/ (150 KB)
│   ├── activity_main.xml
│   ├── fragment_user.xml
│   └── item_list.xml
└── values/ (80 KB)
    ├── strings.xml
    ├── colors.xml
    └── styles.xml
```

**Détection de problèmes :**

* ⚠️ Ressources dupliquées
* ⚠️ Grandes images non optimisées
* ⚠️ Densités manquantes
* ⚠️ Ressources non utilisées (si shrinking pas activé)

**4. Inspection du Manifest**

**Vue décompilée du AndroidManifest.xml :**

L'APK Analyzer convertit le XML binaire en format lisible pour vous montrer :

* Toutes les permissions déclarées
* Les activités et leurs intent-filters
* Les services et broadcast receivers
* Les métadonnées
* Les versions SDK

**Exemple de vue :**

```xml
<manifest package="com.example.app">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    
    <application>
        <activity android:name=".MainActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**5. Compare APKs (Comparer des APK)**

**Fonctionnalité puissante :** Comparez deux versions de votre APK pour voir ce qui a changé.

**Exemple de comparaison v1.0 vs v1.1 :**

```
Fichier              v1.0      v1.1     Différence
─────────────────────────────────────────────────
classes.dex        2.8 MB    3.2 MB    +400 KB ⬆️
res/drawable/      1.5 MB    1.0 MB    -500 KB ⬇️
lib/               800 KB    1.2 MB    +400 KB ⬆️
Total:             6.5 MB    6.8 MB    +300 KB
```

**Utilité :**

* Traquer les augmentations de taille inattendues
* Vérifier l'impact de nouvelles dépendances
* Valider les optimisations

#### <mark style="color:green;">Cas d'Usage Pratiques</mark>

**Cas 1 : APK Trop Lourd**

**Problème :** Votre APK fait 15 MB et le Play Store le signale.

**Analyse avec APK Analyzer :**

```
classes.dex:     4.5 MB  (30%)  ⚠️ Trop gros
res/:            6.8 MB  (45%)  ⚠️ Images non optimisées
lib/armeabi-v7a: 2.2 MB  (15%)
lib/arm64-v8a:   2.3 MB  (15%)
assets/:         0.8 MB  (5%)
```

**Actions :**

1. **DEX trop gros** → Vérifiez les dépendances inutilisées
2. **Ressources lourdes** → Compressez les images avec WebP
3. **Multiples libs natives** → Considérez les APK splits par architecture

**Cas 2 : Méthodes Proches de la Limite**

**Problème :** 63 000 méthodes définies, proche de 65 536.

**Analyse :**

```
Defined Methods: 63,245 / 65,536  ⚠️ Danger!

Top contributors:
- com.google.android.gms: 18,000 méthodes
- androidx.*: 15,000 méthodes
- com.squareup.retrofit: 3,500 méthodes
```

**Solutions :**

1.  Utilisez Play Services de manière sélective

    ```gradle
    implementation 'com.google.android.gms:play-services-maps:18.0.0'
    // Au lieu de
    implementation 'com.google.android.gms:play-services:18.0.0'
    ```
2.  Activez le multidex

    ```gradle
    android {
        defaultConfig {
            multiDexEnabled true
        }
    }
    ```
3. Utilisez R8 avec shrinking agressif

**Cas 3 : Trouver les Ressources Lourdes**

**Tri par taille dans APK Analyzer :**

```
res/drawable/
├── background_hero.png    2.3 MB  ⚠️⚠️⚠️
├── tutorial_video.mp4     1.8 MB  ⚠️⚠️
├── splash_animation.gif   0.9 MB  ⚠️
├── icon_large.png         450 KB
└── app_icon.png           120 KB
```

**Optimisations :**

* `background_hero.png` → Convertir en WebP (économie 70%)
* `tutorial_video.mp4` → Héberger en ligne (téléchargement à la demande)
* `splash_animation.gif` → Remplacer par Lottie animation (JSON)

#### <mark style="color:green;">Commandes en Ligne de Commande</mark>

Pour l'automatisation dans votre CI/CD :

```bash
# Obtenir la taille de l'APK
apkanalyzer apk-summary app-release.apk

# Lister les fichiers dans l'APK
apkanalyzer files list app-release.apk

# Obtenir le compte de méthodes
apkanalyzer dex references app-release.apk

# Comparer deux APK
apkanalyzer apk compare app-v1.apk app-v2.apk

# Extraire le manifest
apkanalyzer manifest print app-release.apk
```

***

### <mark style="color:red;">6. Optimisation de la Taille de l'APK</mark>

#### Pourquoi Optimiser la Taille ?

**Impact direct sur les téléchargements :**

| Taille APK | Taux de conversion   |
| ---------- | -------------------- |
| < 10 MB    | 100% (référence)     |
| 10-20 MB   | -15% téléchargements |
| 20-50 MB   | -30% téléchargements |
| 50-100 MB  | -50% téléchargements |
| > 100 MB   | -70% téléchargements |

**Autres impacts :**

* 📱 Espace de stockage utilisateur
* 📊 Data mobile consommée
* ⏱️ Temps d'installation
* 🌍 Accessibilité dans pays émergents

#### Stratégie 1 : Optimisation du Code

**1.1 Activer R8 (Shrinking + Obfuscation)**

**Configuration build.gradle :**

```gradle
android {
    buildTypes {
        release {
            minifyEnabled true           // Active R8
            shrinkResources true         // Supprime ressources inutilisées
            proguardFiles getDefaultProguardFile(
                'proguard-android-optimize.txt'
            ), 'proguard-rules.pro'
        }
    }
}
```

**Impact typique :**

```
Avant R8:  5.2 MB
Après R8:  2.8 MB  (-46%)
```

**1.2 Gérer les Dépendances**

**Problème commun :**

```gradle
// ❌ Mauvais : importe TOUT Google Play Services (20 MB+)
implementation 'com.google.android.gms:play-services:18.0.0'

// ✅ Bon : seulement ce dont vous avez besoin
implementation 'com.google.android.gms:play-services-maps:18.0.0'
implementation 'com.google.android.gms:play-services-location:18.0.0'
```

**Analyser les dépendances :**

```bash
# Voir toutes les dépendances et leur taille
./gradlew app:dependencies

# Identifier les dépendances transitives
./gradlew app:dependencyInsight --dependency retrofit
```

**Exemple d'optimisation :**

```
Avant (dépendances complètes):
├── play-services:18.0.0        18 MB
├── firebase:28.0.0             12 MB
└── okhttp:4.9.0                 2 MB
Total dépendances: 32 MB

Après (dépendances ciblées):
├── play-services-maps:18.0.0    3 MB
├── firebase-messaging:23.0.0    2 MB
└── okhttp:4.9.0                 2 MB
Total dépendances: 7 MB (-78%)
```

**1.3 Supprimer le Code Mort**

**Configuration R8 agressive :**

```proguard
# proguard-rules.pro

# Optimisations agressives
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-optimizationpasses 5

# Supprimer les logs en production
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# Garde uniquement ce qui est nécessaire
-keep class com.example.models.** { *; }
```

#### <mark style="color:green;">Stratégie 2 : Optimisation des Ressources</mark>

**2.1 Format WebP pour les Images**

**WebP offre une compression supérieure :**

```
PNG:  icon.png      500 KB
      ↓ Conversion
WebP: icon.webp     150 KB  (-70%)
```

**Conversion automatique dans Android Studio :**

1. Clic droit sur image → Convert to WebP
2. Choisir qualité (80-90% recommandé)
3. Preview avant/après

**Support :** Android 4.0+ (99.9% des appareils)

**2.2 Vector Drawables (SVG)**

**Remplacer les images par des vecteurs :**

```
Icône en PNG (tous les DPI):
├── drawable-mdpi/icon.png      12 KB
├── drawable-hdpi/icon.png      18 KB
├── drawable-xhdpi/icon.png     24 KB
├── drawable-xxhdpi/icon.png    36 KB
└── drawable-xxxhdpi/icon.png   48 KB
Total: 138 KB

Icône en Vector Drawable:
└── drawable/icon.xml            2 KB  (-98%)
```

**Exemple de Vector Drawable :**

```xml
<!-- res/drawable/ic_heart.xml -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FF0000"
        android:pathData="M12,21.35l-1.45,-1.32C5.4,15.36 2,12.28 2,8.5 2,5.42 4.42,3 7.5,3c1.74,0 3.41,0.81 4.5,2.09C13.09,3.81 14.76,3 16.5,3 19.58,3 22,5.42 22,8.5c0,3.78 -3.4,6.86 -8.55,11.54L12,21.35z"/>
</vector>
```

**Avantages :**

* Taille minuscule
* Qualité parfaite à toute échelle
* Changement de couleur facile (tint)
* Animations possibles

**2.3 Ressources Alternatives et Configuration Splits**

**Problème :** Votre app supporte 10 langues, mais l'utilisateur n'en utilise qu'une.

**Solution : Configuration Splits**

```gradle
android {
    bundle {
        language {
            enableSplit = true
        }
        density {
            enableSplit = true
        }
        abi {
            enableSplit = true
        }
    }
}
```

**Résultat avec Android App Bundle (AAB) :**

```
Base APK (tous):           5 MB
+ Langue (fr):           + 0.2 MB
+ Densité (xxhdpi):      + 0.8 MB
+ Architecture (arm64):  + 1.5 MB
─────────────────────────────────
Total téléchargé:          7.5 MB

Au lieu de:
APK universel:            15 MB
```

**Économie : 50% de réduction !**

**2.4 Shrink Resources Automatique**

```gradle
android {
    buildTypes {
        release {
            shrinkResources true  // Active le shrinking
            minifyEnabled true    // Requis pour shrinkResources
        }
    }
}
```

**Ce qui est supprimé :**

* Images non référencées
* Layouts inutilisés
* Strings non utilisés
* Ressources alternatives redondantes

**Contrôler le shrinking :**

```xml
<!-- res/raw/keep.xml -->
<resources xmlns:tools="http://schemas.android.com/tools"
    tools:keep="@layout/used_by_reflection,@drawable/legacy_icon"
    tools:discard="@layout/unused_*" />
```

#### <mark style="color:green;">Stratégie 3 : Optimisation des Bibliothèques Natives</mark>

**3.1 Splits par Architecture**

**Problème :** Vous embarquez des libs pour toutes les architectures.

```
lib/
├── armeabi-v7a/
│   └── libnative.so    2.5 MB
├── arm64-v8a/
│   └── libnative.so    3.2 MB
├── x86/
│   └── libnative.so    2.8 MB
└── x86_64/
    └── libnative.so    3.5 MB
Total: 12 MB (mais utilisateur n'en utilise qu'1!)
```

**Solution : ABI Splits**

```gradle
android {
    splits {
        abi {
            enable true
            reset()
            include 'armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64'
            universalApk false  // Ne pas créer d'APK universel
        }
    }
}
```

**Résultat :**

* APK arm64-v8a : 3.2 MB (utilisé par 85% des appareils modernes)
* APK armeabi-v7a : 2.5 MB (appareils anciens)
* APK x86 : 2.8 MB (émulateurs)

**Économie : 75% pour chaque utilisateur !**

**3.2 Utiliser des Bibliothèques Légères**

```gradle
// ❌ Bibliothèque complète
implementation 'com.squareup.okhttp3:okhttp:4.10.0'  // 2 MB

// ✅ Version minimaliste si possible
implementation 'com.squareup.okhttp3:okhttp:4.10.0' {
    exclude group: 'com.squareup.okio', module: 'okio'
}
```

#### <mark style="color:green;">Stratégie 4 : Android App Bundle (AAB)</mark>

**Le format moderne recommandé par Google :**

```
Traditional APK:
└── app-release.apk (15 MB)
    ├── Toutes les langues
    ├── Toutes les densités
    ├── Toutes les architectures
    └── Toutes les ressources

Android App Bundle:
└── app-release.aab (10 MB source)
    → Play Store génère APK optimisés:
    ├── APK base (5 MB)
    ├── + fr.apk (200 KB)
    ├── + xxhdpi.apk (800 KB)
    └── + arm64.apk (1.5 MB)
    
    Utilisateur télécharge: 7.5 MB (-50%)
```

**Configuration :**

```gradle
android {
    bundle {
        language {
            enableSplit = true
        }
        density {
            enableSplit = true
        }
        abi {
            enableSplit = true
        }
    }
}
```

**Build AAB :**

```bash
./gradlew bundleRelease
```

**Avantages :**

* Téléchargements 30-50% plus petits
* Installation plus rapide
* Support des Dynamic Feature Modules
* Requis pour les nouvelles apps sur Play Store

#### <mark style="color:green;">Stratégie 5 : Dynamic Feature Modules</mark>

**Concept :** Télécharger des fonctionnalités à la demande.

**Exemple : App Photo**

```
Base Module (obligatoire):
├── Caméra basique
├── Galerie
└── Interface principale
(3 MB)

Dynamic Feature Modules (optionnels):
├── Filtres Premium      (téléchargé si acheté)
├── Mode Pro             (téléchargé si activé)
└── Éditeur Avancé       (téléchargé si nécessaire)
(1 MB chacun, à la demande)
```

**Structure du projet :**

```
app/                    (module base)
├── src/
└── build.gradle

filters/                (feature module)
├── src/
└── build.gradle

editor/                 (feature module)
├── src/
└── build.gradle
```

**Configuration du feature module :**

```gradle
// filters/build.gradle
plugins {
    id 'com.android.dynamic-feature'
}

android {
    compileSdkVersion 34
}

dependencies {
    implementation project(':app')
}
```

**Télécharger un module à la demande :**

```kotlin
val splitInstallManager = SplitInstallManagerFactory.create(context)

val request = SplitInstallRequest.newBuilder()
    .addModule("filters")
    .build()

splitInstallManager.startInstall(request)
    .addOnSuccessListener {
        // Module installé, lancer la fonctionnalité
    }
    .addOnFailureListener {
        // Gérer l'erreur
    }
```

***

### <mark style="color:blue;">7. Exemples Concrets d'Optimisation</mark>

#### <mark style="color:green;">Exemple 1 : Application de Filtres Photo (Réel)\</</mark>

**État Initial :**

```
app-release.apk: 18.5 MB

Composition:
├── classes.dex          4.2 MB  (23%)
├── lib/                 8.5 MB  (46%)  ⚠️
│   ├── arm64-v8a        4.2 MB
│   ├── armeabi-v7a      2.8 MB
│   └── x86_64           1.5 MB
├── res/                 4.8 MB  (26%)  ⚠️
│   ├── drawable/        4.2 MB  (images samples)
│   └── layout/          0.6 MB
└── assets/              1.0 MB  (5%)
```

**Analyse des Problèmes :**

1. **Lib natives trop lourdes** : 3 architectures × 2.8 MB moyen = gaspillage
2. **Images samples** : 4.2 MB d'exemples de filtres inclus dans l'APK
3. **Pas de compression** : Images PNG non optimisées

**Actions d'Optimisation :**

**Action 1 : ABI Splits**

```gradle
android {
    splits {
        abi {
            enable true
            include 'arm64-v8a', 'armeabi-v7a'
            universalApk false
        }
    }
}
```

Économie : 8.5 MB → 4.2 MB (-50%)

**Action 2 : Dynamic Delivery pour Filtres**

```
Créer module "premium_filters":
- Filtres avancés téléchargés à la demande
- 1.5 MB téléchargé seulement si acheté
```

Économie : -1.5 MB du base APK

**Action 3 : Conversion WebP**

```
Samples PNG → WebP (qualité 85%)
4.2 MB → 1.2 MB (-71%)
```

**Action 4 : R8 + Shrinking**

```gradle
minifyEnabled true
shrinkResources true
```

DEX: 4.2 MB → 2.8 MB (-33%)

**Résultat Final :**

```
app-release.aab génère:
├── APK base (arm64): 6.2 MB  (-66%)
├── APK base (arm32): 5.5 MB  (-70%)
└── Feature (filters): 1.2 MB (optionnel)

Téléchargement typique: 6.2 MB
(au lieu de 18.5 MB)
```
