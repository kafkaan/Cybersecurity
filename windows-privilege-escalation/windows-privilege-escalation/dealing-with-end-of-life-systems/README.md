# Dealing with End of Life Systems

***

* Le module est centré sur les systèmes modernes (Windows 10 / Server 2016).
* Cependant, les systèmes obsolètes (legacy) restent présents, surtout dans les grandes organisations (universités, hôpitaux, administrations).
* Objectif : comprendre les faiblesses spécifiques de ces systèmes pour les identifier lors des évaluations de sécurité.

***

### <mark style="color:$danger;">**Fin de Vie (End of Life - EOL)**</mark>

* Un système est classé en **EOL** quand Microsoft cesse son support (plus de mises à jour de sécurité).
* Phases :
  * Support standard → support étendu → EOL.
* Des contrats personnalisés de support prolongé peuvent exister pour les grandes entreprises.

#### ▶️ **Dates de fin de support – Windows Desktop**

| Version              | Fin de support |
| -------------------- | -------------- |
| Windows XP           | 08/04/2014     |
| Windows Vista        | 11/04/2017     |
| Windows 7            | 14/01/2020     |
| Windows 8            | 12/01/2016     |
| Windows 8.1          | 10/01/2023     |
| Win 10 (1507 → 20H2) | 2017 → 2022    |

#### ▶️ **Dates de fin de support – Windows Server**

| Version          | Fin de support |
| ---------------- | -------------- |
| Server 2003 / R2 | 2014 / 2015    |
| Server 2008 / R2 | 14/01/2020     |
| Server 2012 / R2 | 10/10/2023     |
| Server 2016      | 12/01/2027     |
| Server 2019      | 09/01/2029     |

***

### <mark style="color:$danger;">**Problèmes liés aux systèmes EOL**</mark>

| Problème                   | Description                                                                     |
| -------------------------- | ------------------------------------------------------------------------------- |
| Incompatibilité logicielle | Les applis modernes cessent de fonctionner.                                     |
| Incompatibilité matérielle | Les nouveaux périphériques ne sont plus reconnus.                               |
| **Failles de sécurité**    | Plus de patchs. Exemples : EternalBlue (CVE-2017-0144), SIGRed (CVE-2020-1350). |
| Problèmes organisationnels | Difficulté de mise à jour due à des logiciels métiers critiques non migrables.  |

***

### <mark style="color:$danger;">**Solutions en cas d’impossibilité de mise à jour**</mark>

* **Segmentation réseau stricte**.
* **Isolation des systèmes obsolètes**.
* **Surveillance accrue et restriction des accès**.
* **Communication avec le client pour comprendre les contraintes métier.**

***

### <mark style="color:$danger;">**Implications pour les pentesters**</mark>

* Ces systèmes sont souvent des **points d’entrée faciles** : RCE, LPE, etc.
* Ils peuvent héberger des **applis critiques**, donc prudence avant exploitation.
* Les protections modernes (ASLR, patchs, UAC amélioré…) sont **absentes** ou limitées.
* Objectif : identifier les différences clés entre versions Windows pour adapter les techniques d’escalade de privilèges.

***

### <mark style="color:$danger;">**Versions souvent rencontrées en audit**</mark>

* Encore présentes : **Server 2003, 2008**, parfois **XP**.
* Plus rares mais toujours possibles : **Server 2000**.
* Moins protégées, elles facilitent la compromission de l’environnement.

***
