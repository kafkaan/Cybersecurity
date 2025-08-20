# PrivExchange

### <mark style="color:blue;">PrivExchange</mark>

L'attaque **PrivExchange** exploite une faille dans la fonctionnalité **PushSubscription** d'Exchange Server. Cette faille permet à n'importe quel utilisateur du domaine disposant d'une boîte mail de forcer le serveur Exchange à s'authentifier auprès d'un hôte spécifié par l'attaquant via HTTP.

Le service Exchange s'exécute avec les privilèges **SYSTEM** et est par défaut **sur-privilégié** (c'est-à-dire qu'il possède les droits **WriteDacl** sur le domaine dans les versions antérieures à la mise à jour cumulative de 2019).

Cette vulnérabilité peut être exploitée pour effectuer une attaque **relayée vers LDAP**, permettant ainsi de **récupérer la base NTDS** (contenant les hash des mots de passe du domaine).

Si le relai LDAP n'est pas possible, l'attaque peut toujours être utilisée pour relayer et s'authentifier sur d'autres machines du domaine.

**Avec n'importe quel compte utilisateur authentifié, cette attaque peut directement conduire à l'obtention des privilèges "Domain Admin".**
