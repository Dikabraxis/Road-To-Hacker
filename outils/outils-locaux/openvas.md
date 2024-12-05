# OpenVAS

## OpenVAS - Guide Complet pour la Gestion des Vulnérabilités

***

### &#x20;Introduction

**OpenVAS** (Open Vulnerability Assessment System) est un scanner de vulnérabilités open-source utilisé pour évaluer la sécurité des réseaux. Il permet de :

* Identifier les failles de sécurité sur des serveurs, applications, et réseaux.
* Fournir des recommandations pour la correction des vulnérabilités.
* Gérer et suivre les vulnérabilités à travers des rapports détaillés.

***

### 🚀 Étape 1 : Installation d’OpenVAS

***

#### Installation sur Linux (Debian/Ubuntu)

1.  **Mettre à jour les paquets** :

    ```bash
    sudo apt update && sudo apt upgrade
    ```
2.  **Installer OpenVAS** :

    ```bash
    sudo apt install openvas
    ```
3.  **Configurer OpenVAS** :

    ```bash
    sudo gvm-setup
    ```

    * Cette commande initialise OpenVAS et télécharge les définitions de vulnérabilités.
4.  **Vérifier les services** :

    ```bash
    sudo gvm-check-setup
    ```

#### Accéder à l’interface web

1.  Ouvrez votre navigateur et accédez à :

    ```arduino
    https://localhost:9392
    ```
2. Connectez-vous avec les identifiants fournis après l’installation (affichés lors du `gvm-setup`).

***

### 🛠️ Étape 2 : Scanner un Réseau ou un Système

***

#### Créer une nouvelle tâche de scan via l’interface web

1. Connectez-vous à l’interface web.
2.  Naviguez vers :

    ```arduino
    Scans > Tasks > New Task
    ```

**Configurer la tâche de scan**

| **Paramètre**    | **Description**                                                               |
| ---------------- | ----------------------------------------------------------------------------- |
| **Name**         | Donnez un nom à la tâche (exemple : `Scan Réseau Local`).                     |
| **Scan Targets** | Spécifiez une ou plusieurs cibles (adresse IP, plage d’adresses ou noms DNS). |
| **Scan Config**  | Sélectionnez un profil de scan (par ex. : `Full and Fast`).                   |
| **Scanner**      | Choisissez `OpenVAS Default` comme scanner.                                   |

3. Sauvegardez la tâche et cliquez sur **Start** pour lancer le scan.

#### Visualiser les résultats

1.  Une fois le scan terminé, accédez à :

    ```
    Scans > Reports
    ```
2. Cliquez sur le rapport pour voir les vulnérabilités détectées, classées par gravité :
   * Faible.
   * Moyenne.
   * Haute.
   * Critique.

***

### 🔍 Étape 3 : Gestion des Vulnérabilités

***

#### Analyser les résultats

* Les rapports de vulnérabilités contiennent :
  * **Descriptions des vulnérabilités** (ex. : CVE, CWE).
  * **Conseils de correction**.
  * **Liens vers des ressources supplémentaires**.

#### Créer des tâches de correction

1. Identifiez les vulnérabilités critiques.
2. Dans l’interface, générez des tickets ou des tâches pour corriger les failles.
3. Priorisez les corrections en fonction de :
   * La gravité.
   * L’importance des systèmes affectés.

#### Re-scanner après correction

* Une fois les corrections effectuées, effectuez un **nouveau scan** pour vérifier leur efficacité.

***

### 📋 Étape 4 : Utilisation de l’Interface en Ligne de Commande (CLI)

***

OpenVAS/GVM offre une interface en ligne de commande pour automatiser les scans et interagir avec le gestionnaire de vulnérabilités.

#### Commandes de Base

**1. Liste des commandes disponibles**

```bash
gvm-cli --help
```

**2. Lister les tâches existantes**

```bash
gvm-cli --gmp-username <username> --gmp-password <password> socket --xml "<get_tasks/>"
```

* **Explication** : Affiche toutes les tâches existantes avec leurs ID et paramètres.

**3. Créer une nouvelle tâche**

```bash
gvm-cli --gmp-username <username> --gmp-password <password> socket --xml "<create_task><name>New Task</name><config id='<config_id>'/><target id='<target_id>'/></create_task>"
```

* **Paramètres** :
  * `<config_id>` : ID de la configuration de scan (obtenu via `<get_configs/>`).
  * `<target_id>` : ID de la cible (obtenu via `<get_targets/>`).

**4. Démarrer une tâche existante**

```bash
gvm-cli --gmp-username <username> --gmp-password <password> socket --xml "<start_task task_id='<task_id>'/>"
```

* **Explication** : Lance une tâche de scan avec l’ID de tâche `<task_id>`.

**5. Vérifier l’état d’une tâche**

```bash
gvm-cli --gmp-username <username> --gmp-password <password> socket --xml "<get_tasks task_id='<task_id>'/>"
```

* **Explication** : Vérifie l’état d’avancement d’un scan (en cours, terminé, etc.).

***

### 📖 Étape 5 : Bonnes Pratiques

***

#### 1. Obtenir des autorisations légales

* Scannez uniquement des réseaux pour lesquels vous avez une autorisation explicite.
* Documentez vos actions pour éviter tout malentendu.

#### 2. Limiter la portée des scans

* **Utilisez des plages IP spécifiques** pour éviter de scanner des systèmes hors périmètre autorisé.
* Ajustez la configuration du scan pour inclure uniquement les tests nécessaires.

#### 3. Effectuer les scans pendant les heures creuses

* Les scans peuvent consommer beaucoup de ressources réseau.
* Planifiez vos scans en dehors des heures de pointe pour minimiser l’impact.

#### 4. Analyser les résultats en détail

* Examinez les vulnérabilités critiques pour comprendre leur impact potentiel.
* Collaborez avec les équipes techniques pour hiérarchiser les corrections.

#### 5. Automatiser et Planifier les Scans

* Utilisez la CLI pour planifier des scans réguliers.
* Configurez des alertes pour être notifié en cas de découverte de vulnérabilités critiques.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
