# Bleeding Edge Vulnerabilities

***

### <mark style="color:red;">Windows Defender & SMBEXEC.py Considerations</mark>

Si Windows Defender (ou un autre antivirus/EDR) est activé sur la cible, la session shell peut s’établir, mais l’exécution des commandes échouera probablement. smbexec.py crée d’abord un service appelé **BTOBTO**, puis un second service **BTOBO**. Chaque commande est envoyée à la cible via SMB sous forme de fichier batch `execute.bat`, qui est créé, exécuté puis supprimé automatiquement. Windows Defender détecte ce comportement comme malveillant, générant des alertes dans ses logs.

<mark style="color:green;">**Windows Defender Quarantine Log**</mark>

<figure><img src="../../../.gitbook/assets/defenderLog.webp" alt=""><figcaption></figcaption></figure>

If opsec or being "quiet" is a consideration during an assessment, we would most likely want to avoid a tool like smbexec.py. The focus of this module is on tactics and techniques. We will refine our methodology as we progress in more advanced modules, but we first must obtain a solid base in enumerating and attacking Active Directory.

***

***
