# Metasploit

{% embed url="https://cloud.google.com/blog/topics/threat-intelligence/shikata-ga-nai-encoder-still-going-strong/?hl=en" %}

{% embed url="https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/" %}

{% embed url="https://hatching.io/blog/metasploit-payloads2/" %}

{% embed url="https://www.blackhillsinfosec.com/modifying-metasploit-x64-template-for-av-evasion/" %}

## <mark style="color:red;">**1. Introduction à Metasploit**</mark>

* **Metasploit Project** : Plateforme modulaire de tests d'intrusion écrite en Ruby, permettant d'écrire, tester et exécuter du code d'exploitation.
* **Utilisation principale** : Tester les vulnérabilités de sécurité, analyser les réseaux, exécuter des attaques et éviter la détection.
* **Outils intégrés** : Fournit des modules d'exploitation, des payloads, des outils de post-exploitation, etc.
* **Exploitation modulaire** : La plateforme contient des _proof-of-concepts_ testés et intégrés, facilitant l'accès aux vecteurs d'attaque pour divers systèmes et services.

***

## <mark style="color:red;">**2. Metasploit Framework vs Metasploit Pro**</mark>

* **Metasploit Framework (gratuit)** :
  * Console `msfconsole` : Interface tout-en-un permettant d'accéder aux fonctionnalités de la plateforme.
  * Base de modules extensible (exploits, payloads, scripts).
* **Metasploit Pro (version payante)** :
  * Inclut des fonctionnalités avancées comme l'ingénierie sociale, la validation de vulnérabilités, l'interface graphique, et l'intégration avec Nexpose.
  * Outils pour automatiser et faciliter les tests de pénétration.

***

## <mark style="color:red;">**3. Structure de Metasploit Framework**</mark>

* **Chemin par défaut** : `/usr/share/metasploit-framework` (sur ParrotOS et autres distributions).
* **Dossiers clés** :
  * **Data/Documentation/Lib** : Fichiers de base et documentation.
  * **Modules** : Répartis en `exploits`, `payloads`, `post`, etc.
  * **Plugins** : Ajoutent des fonctionnalités supplémentaires (ex. : `nexpose.rb`, `sqlmap.rb`).
  * **Scripts** : Scripts utiles pour _Meterpreter_ et autres.
  * **Tools** : Utilitaires en ligne de commande (ex. : `recon`, `exploit`).

***

## <mark style="color:red;">**4. Modules de Metasploit**</mark>

* **Exploits** : Attaques pour exploiter des vulnérabilités connues.
* **Payloads** : Code exécuté après l'exploitation (ex. : reverse shells).
* **Auxiliary** : Fonctions non-exploitatives (ex. : scans).
* **Post** : Actions post-exploitation (escalade de privilèges, collecte d'informations).
* **Encoders/Nops** : Contournent la détection des antivirus.
* **Commandes utiles** :
  * `search type:exploit name:cve-2021-xyz` : Rechercher un exploit.
  * `use exploit/windows/smb/ms17_010_eternalblue` : Charger un module d'exploitation.
  * `set RHOSTS <ip_cible>` : Définir la cible.
  * `run` ou `exploit` : Lancer l'attaque.

<figure><img src="../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>
