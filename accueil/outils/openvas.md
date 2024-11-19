# OpenVAS

#### Introduction

OpenVAS (Open Vulnerability Assessment System) est un scanner de vulnérabilités open-source utilisé pour identifier et gérer les vulnérabilités dans les systèmes et les réseaux. Il fait partie de la suite Greenbone Vulnerability Management (GVM).

#### Installation d'OpenVAS

**Installation sur Debian/Ubuntu**

1.  **Ajouter le dépôt Greenbone** :

    ```bash
    sudo add-apt-repository ppa:mrazavi/gvm
    ```

    * **Explication** : Ajoute le dépôt PPA pour installer les paquets OpenVAS.


2.  **Mettre à jour les paquets et installer OpenVAS** :

    ```bash
    sudo apt update
    sudo apt install gvm
    ```

    * **Explication** : Met à jour la liste des paquets et installe OpenVAS.


3.  **Configurer et initialiser OpenVAS** :

    ```bash
    sudo gvm-setup
    ```

    * **Explication** : Configure et initialise OpenVAS.


4.  **Vérifier l'installation** :

    ```bash
    sudo gvm-check-setup
    ```

    * **Explication** : Vérifie que l'installation d'OpenVAS a été effectuée correctement.



#### Utilisation d'OpenVAS

**Démarrage et Accès à l'Interface Web**

1.  **Démarrer les services OpenVAS** :

    ```bash
    sudo gvm-start
    ```

    * **Explication** : Démarre les services nécessaires pour OpenVAS.


2.  **Accéder à l'interface web** :

    * Ouvrir un navigateur web et naviguer vers : `https://localhost:9392`
    * Se connecter avec les informations d'identification fournies lors de la configuration initiale.



**Scanner un Réseau ou un Système**

1. **Créer une nouvelle tâche de scan**
   * Aller dans l'interface web d'OpenVAS.
   * Cliquer sur "Scans" > "Tasks" > "New Task".
2.  **Configurer la tâche de scan**

    * **Name** : Donner un nom à la tâche.
    * **Scan Targets** : Spécifier les cibles (adresse IP ou plage d'adresses).
    * **Scan Config** : Choisir une configuration de scan (par exemple, "Full and fast").
    * **Scanner** : Utiliser le scanner par défaut (OpenVAS Default).


3.  **Lancer la tâche de scan**

    * Sauvegarder la tâche et cliquer sur "Start".


4.  **Visualiser les résultats**

    * Aller dans "Scans" > "Reports" pour voir les résultats du scan une fois terminé.



**Gestion des Vulnérabilités**

1.  **Analyser les résultats**

    * Dans la section "Reports", cliquer sur le rapport du scan pour voir les détails des vulnérabilités détectées.


2.  **Créer des tickets ou des tâches de correction**

    * Identifier les vulnérabilités critiques et créer des tickets pour les corriger.
    * Prioriser les tâches en fonction de la gravité des vulnérabilités.


3.  **Re-scanner après correction**

    * Après avoir corrigé les vulnérabilités, re-scannez les cibles pour vérifier que les corrections ont été effectuées avec succès.



#### Options Avancées

**Utilisation de l'Interface en Ligne de Commande**

OpenVAS fournit des outils en ligne de commande pour interagir avec le gestionnaire de vulnérabilités.

1.  **Liste des commandes disponibles**

    ```bash
    gvm-cli --help
    ```

    * **Explication** : Affiche l'aide pour les commandes disponibles de gvm-cli.


2.  **Lister les tâches existantes**

    ```bash
    gvm-cli --gmp-username <username> --gmp-password <password> socket --xml "<get_tasks/>"
    ```

    * **Explication** : Liste toutes les tâches existantes dans OpenVAS.


3.  **Créer une nouvelle tâche via CLI**

    ```bash
    gvm-cli --gmp-username <username> --gmp-password <password> socket --xml "<create_task><name>New Task</name><config id='<config_id>'/><target id='<target_id>'/></create_task>"
    ```

    * **Explication** : Crée une nouvelle tâche de scan via la ligne de commande.


4.  **Lancer une tâche via CLI**

    ```bash
    gvm-cli --gmp-username <username> --gmp-password <password> socket --xml "<start_task task_id='<task_id>'/>"
    ```

    * **Explication** : Démarre une tâche de scan existante via la ligne de commande.


5.  **Vérifier l'état d'une tâche via CLI**

    ```bash
    gvm-cli --gmp-username <username> --gmp-password <password> socket --xml "<get_tasks task_id='<task_id>'/>"
    ```

    * **Explication** : Vérifie l'état d'une tâche de scan existante via la ligne de commande.



#### Bonnes Pratiques

1.  **Obtenir des Autorisations**

    * **Assurez-vous toujours** d'avoir les autorisations nécessaires avant de scanner des réseaux ou des systèmes.


2.  **Limiter la portée des scans**

    * Spécifier des plages d'adresses IP précises pour éviter d'affecter des systèmes non ciblés.


3.  **Planifier les scans pendant les heures creuses**

    * Effectuer les scans pendant les périodes de faible activité pour minimiser l'impact sur les performances du réseau.


4.  **Analyser les résultats en détail**

    * Examiner attentivement les rapports de vulnérabilités pour comprendre les implications et prioriser les corrections.

