# Rpcclient

### **RPCClient - Guide Complet pour l’Exploration et la Gestion des Partages Windows**

***

### **Introduction**

**RPCClient** est un outil interactif inclus dans la suite **Samba**, utilisé pour interagir avec les services RPC (Remote Procedure Call) sur les systèmes Windows. Il est principalement utilisé dans des contextes de tests d'intrusion, de gestion des partages réseau ou d'administration pour interroger et manipuler les ressources partagées par un serveur Windows.

***

### **🚀 Étape 1 : Installation de RPCClient**

**1. Installation sur Linux (Debian/Ubuntu)**

1.  Mettez à jour vos paquets :

    ```bash
    sudo apt update
    ```
2.  Installez Samba :

    ```bash
    sudo apt install samba
    ```

    Cela installe **rpcclient** ainsi que d'autres outils Samba.
3.  Vérifiez l’installation :

    ```bash
    rpcclient --version
    ```

    Vous devriez voir la version de l’outil affichée.

***

**2. Installation sur macOS**

1.  Installez Homebrew (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2.  Installez Samba via Homebrew :

    ```bash
    bashCopier le codebrew install samba
    ```
3.  Vérifiez l'installation :

    ```bash
    rpcclient --version
    ```

***

**3. Installation sur Windows**

**RPCClient** n’est pas directement disponible pour Windows. Vous pouvez l’utiliser dans un environnement Linux, macOS, ou dans une machine virtuelle contenant un système compatible.

***

### **🛠️ Étape 2 : Utilisation de Base de RPCClient**

RPCClient est un outil en ligne de commande qui fonctionne en session interactive ou via des commandes exécutées directement. Voici les étapes de base pour s’y connecter et explorer un serveur.

***

**1. Connexion à un Serveur**

Commande :

```bash
rpcclient -U username //target_ip_or_hostname
```

**Explications :**

* `-U username` : Spécifie le nom d’utilisateur pour l’authentification.
* `//target_ip_or_hostname` : Adresse IP ou nom d’hôte de la cible.

Exemple avec un utilisateur `admin` et un serveur à l’adresse `192.168.1.10` :

```bash
rpcclient -U admin //192.168.1.10
```

Vous serez invité à entrer un mot de passe.

***

**2. Connexion avec une Session Nulle**

Si l’authentification anonyme est autorisée sur le serveur :

```bash
rpcclient -N //target_ip_or_hostname
```

**Explications :**

* `-N` : Connexion sans mot de passe (Session Nulle).

***

**3. Tester la Connexion**

Pour vérifier si le serveur répond correctement, utilisez la commande :

```bash
rpcclient -U username //target_ip_or_hostname -c 'srvinfo'
```

***

### **🔍 Étape 3 : Commandes Essentielles de RPCClient**

Une fois connecté au serveur, vous pouvez exécuter plusieurs commandes pour explorer et interagir avec les ressources du serveur. Voici les principales commandes.

***

**1. Obtenir des Informations sur le Serveur**

Commande :

```bash
srvinfo
```

**Explications :**

* Retourne des informations sur le système d’exploitation du serveur, sa version et son architecture.

***

**2. Lister les Utilisateurs**

Commande :

```bash
enumdomusers
```

**Explications :**

* Retourne une liste des utilisateurs présents sur le domaine ou sur la machine cible.

***

**3. Récupérer des Informations sur un Utilisateur**

Commande :

```bash
queryuser username
```

**Explications :**

* Affiche des informations sur un utilisateur spécifique, comme la dernière connexion, l’expiration du mot de passe, etc.

Exemple :

```bash
queryuser admin
```

***

**4. Lister les Groupes Locaux**

Commande :

```bash
enumalsgroups
```

**Explications :**

* Retourne les groupes locaux configurés sur la machine cible.

***

**5. Enumérer les Partages Réseau**

Commande :

```bash
netshareenum
```

**Explications :**

* Affiche une liste des ressources partagées (répertoires ou imprimantes) sur le serveur.

***

**6. Obtenir des Détails sur un Partage**

Commande :

```bash
netsharegetinfo sharename
```

**Explications :**

* Fournit des informations détaillées sur un partage spécifique.

Exemple :

```bash
netsharegetinfo C$
```

***

**7. Lancer une Commande Personnalisée**

Commande :

```bash
cmd command
```

**Explications :**

* Permet d’exécuter des commandes spécifiques si l’utilisateur possède les droits suffisants.

***

**8. Réinitialiser un Mot de Passe**

Si vous avez les permissions nécessaires :

```bash
setuserinfo2 username 23 newpassword
```

**Explications :**

* Réinitialise le mot de passe d’un utilisateur. Cela peut être utile pour l’administration ou les tests d’intrusion autorisés.

***

### **📋 Étape 4 : Exemples de Scénarios Pratiques**

**1. Exploration des Partages Réseau**

1.  Connectez-vous au serveur :

    ```bash
    rpcclient -U admin //192.168.1.10
    ```
2.  Listez les partages disponibles :

    ```bash
    netshareenum
    ```
3.  Obtenez des détails sur un partage spécifique :

    ```bash
    netsharegetinfo sharedocs
    ```

***

**2. Récupération de la Liste des Utilisateurs**

1.  Connectez-vous avec une session nulle :

    ```bash
    rpcclient -N //192.168.1.10
    ```
2.  Listez les utilisateurs :

    ```bash
    enumdomusers
    ```

***

**3. Audit des Groupes Locaux**

1.  Connectez-vous au serveur :

    ```bash
    rpcclient -U admin //192.168.1.10
    ```
2.  Listez les groupes locaux :

    ```bash
    enumalsgroups
    ```

***

**4. Test de la Sécurité**

Exemple : Vérifier si les sessions nulles sont activées sur le serveur.

1.  Connectez-vous sans mot de passe :

    ```bash
    rpcclient -N //192.168.1.10
    ```
2.  Essayez de récupérer des informations comme les utilisateurs ou les partages :

    ```bash
    enumdomusers
    ```

***

### **🔧 Options Avancées et Optimisation**

**1. Lancer Plusieurs Commandes Automatiquement**

Utilisez le paramètre `-c` pour exécuter plusieurs commandes en une seule ligne :

```bash
rpcclient -U admin //192.168.1.10 -c "srvinfo; enumdomusers; netshareenum"
```

***

**2. Utiliser un Fichier de Commandes**

Créez un fichier, par exemple `commands.txt`, contenant :

```
srvinfo
enumdomusers
netshareenum
```

Puis exécutez-le :

```bash
rpcclient -U admin //192.168.1.10 < commands.txt
```

***

**3. Réduire les Faux Positifs**

Affinez vos commandes pour obtenir des résultats pertinents en combinant des commandes d’exploration et des analyses spécifiques.

***

### **📖 Bonnes Pratiques avec RPCClient**

1. **Travaillez avec Autorisation :** N’utilisez jamais RPCClient pour interagir avec des systèmes sans autorisation préalable.
2. **Notez les Résultats :** Exportez vos découvertes pour les analyser ou les documenter ultérieurement.
3. **Associez avec d’autres outils :** Combinez RPCClient avec Nmap ou SMBClient pour une analyse approfondie.
4. **Testez la Sécurité :** Vérifiez si des sessions nulles ou des configurations faibles sont activées sur vos serveurs pour les corriger.
