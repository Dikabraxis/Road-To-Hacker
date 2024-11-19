# Feroxbuster

## FeroxBuster - Guide Complet pour la Découverte de Contenu Web

***

### Introduction

**FeroxBuster** est un outil de fuzzing web performant utilisé pour identifier des fichiers et répertoires cachés sur des serveurs web. Grâce à sa rapidité et sa flexibilité, il est particulièrement adapté pour :

* **La découverte de contenu web** non référencé.
* **L'audit de sécurité** pour identifier des ressources exposées ou vulnérables.
* **Le pentesting** pour révéler des informations sensibles sur un serveur.

#### Points forts :

* Multithreading pour une performance maximale.
* Support des listes de mots personnalisées.
* Capacité à scanner récursivement des répertoires découverts.

***

### 🚀 Étape 1 : Installation de FeroxBuster

***

#### Prérequis

*   **Curl** : Vérifiez si `curl` est installé sur votre système :

    ```bash
    curl --version
    ```

    Si non :

    *   **Linux** :

        ```bash
        sudo apt install curl
        ```
    *   **macOS** :

        ```bash
        brew install curl
        ```
* **Rust** : FeroxBuster est écrit en Rust, donc Rust peut être nécessaire pour certaines méthodes d'installation.
  *   Vérifiez si Rust est installé :

      ```bash
      rustc --version
      ```
  *   Si non, installez-le avec :

      ```bash
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
      ```

***

#### Installation sur Linux/macOS

1. **Installer via le script officiel** :
   *   Téléchargez et installez automatiquement la dernière version :

       ```bash
       curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
       ```
2. **Vérifier l'installation** :
   *   Testez l'installation en exécutant :

       ```bash
       feroxbuster --version
       ```

***

#### Installation sur Windows

1. **Télécharger les binaires précompilés** :
   * Rendez-vous sur la [page des releases GitHub de FeroxBuster](https://github.com/epi052/feroxbuster/releases).
   * Téléchargez le fichier **ZIP** correspondant à votre système.
2. **Décompresser et configurer le PATH** :
   * Extrayez le contenu du fichier ZIP dans un répertoire de votre choix.
   * Ajoutez ce répertoire au **PATH** de votre système :
     * Accédez à **Paramètres > Système > Paramètres système avancés > Variables d'environnement**.
     * Ajoutez le chemin du répertoire contenant `feroxbuster.exe` dans la variable `PATH`.
3. **Vérifier l'installation** :
   *   Ouvrez une invite de commande et exécutez :

       ```bash
       feroxbuster --version
       ```

***

### 🚀 Étape 2 : Utilisation de Base de FeroxBuster

***

#### 1. Découverte de Répertoires et Fichiers

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com
    ```
* **Explication** :
  * `-u` : Spécifie l’URL cible.
  * Utilise les listes de mots intégrées pour identifier les répertoires et fichiers cachés.

> 💡 **Astuce** : Ajoutez l’option `-v` pour activer un mode verbeux et afficher plus de détails sur le scan.

***

#### 2. Scanner avec une Liste de Mots Personnalisée

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com -w path/to/wordlist.txt
    ```
* **Explication** :
  * `-w` : Spécifie une liste de mots personnalisée.
  * Remplacez `path/to/wordlist.txt` par le chemin vers votre wordlist.

***

#### 3. Enregistrement des Résultats

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com -o results.txt
    ```
* **Explication** :
  * `-o` : Enregistre les résultats du scan dans le fichier spécifié (`results.txt`).

***

### 🔍 Étape 3 : Options Avancées et Optimisation

***

#### 1. Ignorer des Codes de Statut HTTP

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com --filter-status 404,403
    ```
* **Explication** :
  * `--filter-status` : Ignore les réponses avec les codes de statut HTTP `404` (non trouvé) et `403` (accès refusé).

***

#### 2. Scanner des Extensions de Fichiers Spécifiques

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com -x php,html,js
    ```
* **Explication** :
  * `-x` : Cible uniquement les fichiers avec les extensions spécifiées (`.php`, `.html`, `.js`).

***

#### 3. Scanner Récursivement

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com --recurse
    ```
* **Explication** :
  * `--recurse` : Explore automatiquement les répertoires trouvés pour effectuer des scans supplémentaires.

***

#### 4. Ajouter un Délai entre les Requêtes

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com --delay 200ms
    ```
* **Explication** :
  * `--delay` : Ajoute un délai de 200ms entre les requêtes pour réduire l’impact sur le serveur cible.

***

#### 5. Limiter le Scan à une Taille de Réponse

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com --filter-size 0
    ```
* **Explication** :
  * `--filter-size` : Ignore les réponses avec une taille de contenu de `0` (souvent des pages vides).

***

### 📋 Étape 4 : Exemples de Scénarios Pratiques

***

#### 1. Découverte de Panneaux d’Administration

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com -w path/to/admin_wordlist.txt -x php
    ```
* **Explication** :
  * Utilise une liste de mots spécifique pour découvrir des panneaux d'administration web (`admin.php`, `login.php`).

***

#### 2. Audit de Sécurité Complet

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com --recurse -w path/to/wordlist.txt -x php,html,js --filter-size 0
    ```
* **Explication** :
  * Effectue un scan récursif en ciblant des extensions spécifiques et en filtrant les réponses inutiles.

***

#### 3. Découverte de Fichiers Sensibles

*   **Commande** :

    ```bash
    feroxbuster -u http://example.com -x bak,old,log,zip
    ```
* **Explication** :
  * Recherche des fichiers associés à des sauvegardes ou des journaux (`.bak`, `.old`, `.log`, `.zip`).

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations légales** :
   * Avant de scanner un serveur, assurez-vous d’avoir l’autorisation explicite du propriétaire.
2. **Limitez l’impact sur le serveur** :
   * Utilisez des options comme `--delay` pour réduire la charge générée par vos scans.
3. **Analysez les résultats soigneusement** :
   * Les résultats peuvent inclure des faux positifs ; vérifiez les réponses manuellement si nécessaire.
4. **Combinez FeroxBuster avec d’autres outils** :
   * Associez FeroxBuster à des outils comme **Burp Suite** pour enrichir vos découvertes.
