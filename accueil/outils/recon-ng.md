# Recon-ng

## Recon-ng - Guide Complet

***

### Introduction

**Recon-ng** est un framework puissant conçu pour la collecte d'informations lors d'un test de pénétration ou d'une analyse OSINT (Open Source Intelligence). Recon-ng se concentre sur la collecte et la structuration des données à partir de sources publiques, avec des modules spécialisés pour différents types d'informations (emails, réseaux sociaux, sous-domaines, etc.).

***

### 🚀 Étape 1 : Installation de Recon-ng

***

#### Sous Linux (Debian/Ubuntu)

1.  **Mettre à jour les paquets** :

    ```bash
    sudo apt update && sudo apt upgrade
    ```
2.  **Installer Recon-ng via GitHub** :

    ```bash
    git clone https://github.com/lanmaster53/recon-ng.git
    cd recon-ng
    pip install -r REQUIREMENTS
    ```
3.  **Lancer Recon-ng** :

    ```bash
    ./recon-ng
    ```

***

### 🚀 Étape 2 : Concepts Clés

***

#### 1. Les Espaces de Travail

Recon-ng organise les données dans des espaces de travail. Cela permet de structurer vos projets et de séparer les analyses pour différentes cibles.

**Commandes Utiles :**

*   **Créer un nouvel espace de travail** :

    ```bash
    workspaces create <workspace_name>
    ```
*   **Lister les espaces de travail existants** :

    ```bash
    workspaces list
    ```
*   **Changer d’espace de travail** :

    ```bash
    workspaces select <workspace_name>
    ```
*   **Exporter un espace de travail** :

    ```bash
    workspaces export <file_name>.json
    ```

***

#### 2. Les Modules

Recon-ng dispose d'une large bibliothèque de modules pour différents objectifs :

* **recon** : Modules de collecte d'informations sur les domaines, emails, IPs, réseaux sociaux, etc.
* **reporting** : Modules pour exporter les résultats sous forme de fichiers ou rapports.
* **exploitation** : Modules pour exploiter des données collectées, comme l'interrogation de bases de données vulnérables.

**Commandes Utiles :**

*   **Lister les modules disponibles** :

    ```bash
    modules search <keyword>
    ```
*   **Charger un module** :

    ```bash
    modules load <module_path>
    ```
*   **Afficher les options d’un module** :

    ```bash
    show options
    ```
*   **Configurer une option** :

    ```bash
    options set <option_name> <value>
    ```
*   **Exécuter le module** :

    ```bash
    run
    ```

***

### 🚀 Étape 3 : Utilisation des Modules

***

#### 1. Collecte d’Adresses Email

Pour collecter les emails associés à un domaine cible :

```bash
modules load recon/emails-contacts/emailharvest
options set SOURCE <domain>
run
```

* **Explication** :
  * `emailharvest` recherche des adresses email publiques associées à un domaine.
  * Remplacez `<domain>` par le domaine cible (par exemple : example.com).

***

#### 2. Découverte des Sous-Domaines

Pour rechercher les sous-domaines associés à un domaine :

```bash
modules load recon/domains-hosts/subdomain_brute
options set SOURCE <domain>
run
```

* **Explication** :
  * `subdomain_brute` effectue une attaque par dictionnaire pour trouver les sous-domaines.
  * Remplacez `<domain>` par le domaine cible.

***

#### 3. Analyse des Réseaux Sociaux

Pour collecter des informations publiques sur les réseaux sociaux (par exemple, Facebook) :

```bash
modules load recon/contacts-social/facebook
options set SOURCE <username>
run
```

* **Explication** :
  * `facebook` extrait des données associées à un utilisateur sur Facebook.
  * Remplacez `<username>` par le nom d'utilisateur cible.

***

#### 4. Collecte des En-Têtes HTTP

Pour analyser les en-têtes HTTP d'un domaine ou d'une IP :

```bash
modules load recon/hosts-hosts/http_header
options set SOURCE <domain>
run
```

* **Explication** :
  * `http_header` interroge les en-têtes HTTP d'un domaine ou d'une adresse IP.
  * Remplacez `<domain>` par le domaine cible (par exemple : example.com).

***

### 🚀 Étape 4 : Exportation des Résultats

***

#### 1. Exporter les Résultats Collectés

Pour afficher et sauvegarder les résultats collectés :

```bash
show hosts
save <file_name>.csv
```

* **Explication** :
  * `show hosts` liste les hôtes collectés.
  * `save` exporte les résultats au format CSV.

***

#### 2. Sauvegarder l’Espace de Travail

Pour sauvegarder un espace de travail complet (données + configuration) :

```bash
workspaces export <file_name>.json
```

* **Explication** :
  * Exporte l’espace de travail dans un fichier JSON pour une utilisation ultérieure.

***

### 📋 Scénarios d’Utilisation

***

#### Exemple 1 : Collecte Complète sur un Domaine

1.  **Créer un espace de travail** :

    ```bash
    workspaces create example_workspace
    ```
2.  **Rechercher des sous-domaines et des IPs associées** :

    ```bash
    modules load recon/domains-hosts/subdomain_brute
    options set SOURCE example.com
    run
    ```
3.  **Collecter des emails publics associés au domaine** :

    ```bash
    modules load recon/emails-contacts/emailharvest
    options set SOURCE example.com
    run
    ```
4.  **Exporter les résultats** :

    ```bash
    show hosts
    save example_results.csv
    ```

***

#### Exemple 2 : Analyse des Réseaux Sociaux

1.  **Rechercher des informations sur un utilisateur Facebook** :

    ```bash
    modules load recon/contacts-social/facebook
    options set SOURCE target_username
    run
    ```
2.  **Afficher les résultats collectés** :

    ```bash
    show contacts
    ```

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations

* **Respectez la légalité** : Ne collectez que des informations pour lesquelles vous avez des autorisations explicites.
* **Évitez les abus** : Ne surchargez pas les serveurs ou services en lançant des requêtes excessives.

#### 2. Utiliser des Sources Publiques

* Limitez vos recherches aux sources accessibles publiquement pour éviter les détections et alertes.

#### 3. Optimiser les Requêtes

* Réduisez l’impact des modules en limitant la fréquence des requêtes.
* Privilégiez des modules ciblés pour éviter de collecter des informations inutiles.

***

### Conclusion

**Recon-ng** est un outil puissant pour la collecte d’informations dans les tests de pénétration et les analyses OSINT. Grâce à ses nombreux modules et à son organisation en espaces de travail, il permet de structurer et d’automatiser vos recherches tout en exportant les résultats sous différents formats.
