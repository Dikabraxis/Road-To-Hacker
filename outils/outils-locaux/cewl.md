# Cewl

## Cewl - Générateur de Dictionnaires à partir de Sites Web

***

### Introduction

**Cewl** (Custom Word List Generator) est un outil puissant qui permet d'extraire des mots d'un site web pour générer des dictionnaires personnalisés. Ces dictionnaires peuvent être utilisés dans des attaques par force brute ou pour des audits de sécurité.

#### Pourquoi utiliser Cewl ?

* **Extraction ciblée** : Génère un dictionnaire basé sur le contenu d’un site précis.
* **Options de personnalisation** : Permet de filtrer les mots par longueur, profondeur de navigation, et bien plus.
* **Pratique pour les tests de mots de passe** : Idéal pour les audits de sécurité ou les exercices de pentesting.

***

### 🚀 Installation de Cewl

#### Prérequis

* **Ruby** : Cewl est écrit en Ruby, il nécessite donc que Ruby soit installé.

#### Installation sur Linux (exemple : Ubuntu)

1.  **Mettre à jour la liste des paquets disponibles** :

    ```bash
    sudo apt update
    ```

    * **Explication** : Actualise la liste des paquets disponibles pour s'assurer d'installer la dernière version.
2.  **Installer Ruby** :

    ```bash
    sudo apt install ruby
    ```

    * **Explication** : Installe Ruby via le gestionnaire de paquets `apt`.
3.  **Installer Cewl via RubyGems** :

    ```bash
    sudo gem install cewl
    ```

    * **Explication** : Installe Cewl en utilisant le gestionnaire de paquets Ruby (RubyGems).
4.  **Vérifier l’installation** :

    ```bash
    cewl --help
    ```

    * **Explication** : Vérifie que Cewl est correctement installé en affichant le guide d’utilisation.

***

#### Installation sur Windows

1. **Installer Ruby** :
   * Téléchargez Ruby depuis le [site officiel](https://rubyinstaller.org/).
   * Suivez les instructions de l’installateur.
2. **Installer Cewl via RubyGems** :
   *   Ouvrez une invite de commande et exécutez :

       ```bash
       gem install cewl
       ```
   * **Explication** : Installe Cewl sur votre système Windows.
3. **Vérifier l’installation** :
   *   Testez l’installation en exécutant :

       ```bash
       cewl --help
       ```

***

### 🛠️ Utilisation de Base de Cewl

#### 1. Générer un dictionnaire de base

*   **Commande** :

    ```bash
    cewl http://example.com
    ```
* **Explication** :
  * Analyse le contenu du site spécifié (`http://example.com`) et extrait les mots pour les afficher dans le terminal.

***

#### 2. Enregistrer les mots extraits dans un fichier

*   **Commande** :

    ```bash
    cewl http://example.com -w dictionnaire.txt
    ```
* **Explication** :
  * Utilise l'option `-w` pour spécifier un fichier (`dictionnaire.txt`) où les mots extraits seront sauvegardés.

***

#### 3. Explorer les liens avec une profondeur spécifique

*   **Commande** :

    ```bash
    cewl http://example.com --depth 2
    ```
* **Explication** :
  * L'option `--depth` contrôle le niveau d'exploration des liens.
  * Une profondeur de `2` explore les liens de premier et deuxième niveau.

***

#### 4. Filtrer les mots par longueur

*   **Commande** :

    ```bash
    cewl http://example.com --min_length 6 --max_length 12
    ```
* **Explication** :
  * `--min_length 6` : Inclut uniquement les mots contenant au moins 6 caractères.
  * `--max_length 12` : Exclut les mots contenant plus de 12 caractères.

***

### 🔍 Options Avancées

#### 1. Utiliser des cookies pour l’authentification

*   **Commande** :

    ```bash
    cewl http://example.com --cookies "cookie1=value1; cookie2=value2"
    ```
* **Explication** :
  * Ajoute des cookies pour accéder à des pages nécessitant une authentification.

***

#### 2. Ignorer des mots ou balises spécifiques

*   **Commande** :

    ```bash
    cewl http://example.com --ignore_words "javascript:void(0);login;"
    ```
* **Explication** :
  * L'option `--ignore_words` permet d'exclure certains mots indésirables.

***

#### 3. Utiliser un proxy pour l’extraction

*   **Commande** :

    ```bash
    cewl http://example.com --proxy http://localhost:8080
    ```
* **Explication** :
  * Acheminer le trafic via un proxy (ex. : Burp Suite) pour contrôler ou intercepter les requêtes.

***

### 📋 Exemples Pratiques

#### 1. Générer un dictionnaire à partir d’un site web

*   **Commande** :

    ```bash
    cewl http://example.com -w dictionnaire.txt
    ```
* **Explication** :
  * Les mots extraits du site `http://example.com` sont sauvegardés dans `dictionnaire.txt`.

***

#### 2. Générer un dictionnaire avec une profondeur et des filtres

*   **Commande** :

    ```bash
    cewl http://example.com --depth 3 --min_length 8 -w dictionnaire.txt
    ```
* **Explication** :
  * Explore les liens jusqu’à une profondeur de `3`.
  * Extrait uniquement les mots contenant au moins `8 caractères`.

***

### 🎯 Scénarios d’Utilisation

#### Scénario 1 : Utiliser un dictionnaire pour le brute-force

1. **Générer un dictionnaire** :
   *   Exécutez :

       ```bash
       cewl http://target-site.com -w wordlist.txt
       ```
2. **Lancer une attaque brute-force** :
   *   Utilisez un outil comme **Hydra** avec le dictionnaire :

       ```bash
       hydra -l admin -P wordlist.txt http-post-form "/login:username=^USER^&password=^PASS^:F=Incorrect"
       ```

***

#### Scénario 2 : Générer des mots personnalisés pour des attaques ciblées

1. Explorez un site web qui publie régulièrement des informations (ex. : forums, blogs).
2.  Utilisez Cewl pour extraire les mots-clés et former un dictionnaire spécifique :

    ```bash
    cewl http://blog.example.com --depth 2 -w custom-wordlist.txt
    ```

***

### 📖 Bonnes Pratiques et Précautions

1. **Limiter les requêtes** :
   *   Ajoutez un délai entre les requêtes pour éviter de surcharger le serveur :

       ```bash
       cewl http://example.com --delay 5
       ```
2. **Obtenir des autorisations** :
   * Avant d'utiliser Cewl sur un site, obtenez la permission pour éviter des implications légales.
3. **Travailler avec un proxy** :
   * Utilisez un proxy comme Burp Suite pour surveiller les requêtes effectuées par Cewl.
