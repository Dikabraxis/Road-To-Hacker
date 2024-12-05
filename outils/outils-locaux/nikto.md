# Nikto

## Nikto - Guide Complet pour le Scannage de Vulnérabilités Web

***

### Introduction

**Nikto** est un scanner open-source conçu pour identifier les vulnérabilités sur des serveurs web. Il permet de :

* Détecter des configurations incorrectes.
* Identifier des versions vulnérables de logiciels.
* Trouver des fichiers sensibles ou des répertoires exposés.

⚠️ **Note** : Nikto est un outil puissant. Son utilisation doit être accompagnée d'une autorisation légitime du propriétaire du serveur.

***

### 🚀 Étape 1 : Installation de Nikto

***

#### Installation sur Linux (Debian/Ubuntu)

**Via les dépôts apt**

1.  **Mettre à jour la liste des paquets** :

    ```bash
    sudo apt update
    ```
2.  **Installer Nikto** :

    ```bash
    sudo apt install nikto
    ```
3.  **Vérifier l'installation** :

    ```bash
    nikto -Version
    ```

***

#### Installation via Git (Linux/macOS/Windows)

1.  **Cloner le dépôt officiel** :

    ```bash
    git clone https://github.com/sullo/nikto.git
    ```
2.  **Naviguer dans le répertoire** :

    ```bash
    cd nikto/program
    ```
3.  **Lancer Nikto** :

    ```bash
    perl nikto.pl
    ```
4. (Facultatif) Ajouter le chemin au `PATH` pour exécuter Nikto directement depuis n’importe quel répertoire.

***

#### Installation sur Windows

1. **Installer Perl** :
   * Téléchargez ActivePerl et installez-le.
2. **Cloner Nikto** via Git ou téléchargez-le directement depuis GitHub.
3.  **Exécuter Nikto** :

    ```cmd
    perl nikto.pl -Version
    ```

***

### 🛠️ Étape 2 : Commandes de Base

***

#### 1. Effectuer un Scan de Base

*   **Commande** :

    ```bash
    nikto -h <URL>
    ```
*   **Exemple** :

    ```bash
    nikto -h http://example.com
    ```
* **Explication** :
  * `-h` : Spécifie l'hôte ou l'adresse IP du serveur cible.

***

#### 2. Activer le Mode Verbose

*   **Commande** :

    ```bash
    nikto -h <URL> -v
    ```
*   **Exemple** :

    ```bash
    nikto -h http://example.com -v
    ```
* **Explication** :
  * `-v` : Affiche des détails supplémentaires pendant le scan.

***

#### 3. Utiliser une Liste de Mots Personnalisée

*   **Commande** :

    ```bash
    nikto -h <URL> -w <wordlist>
    ```
*   **Exemple** :

    ```bash
    nikto -h http://example.com -w /path/to/wordlist.txt
    ```
* **Explication** :
  * `-w` : Utilise une liste de mots spécifique pour découvrir des chemins ou fichiers supplémentaires.

***

#### 4. Exclure des Fichiers ou Répertoires

*   **Commande** :

    ```bash
    nikto -h <URL> -x <path>
    ```
*   **Exemple** :

    ```bash
    nikto -h http://example.com -x /excluded/path
    ```
* **Explication** :
  * `-x` : Exclut certains chemins pour éviter de scanner des fichiers ou répertoires spécifiques.

***

#### 5. Sauvegarder les Résultats

*   **Commande** :

    ```bash
    nikto -h <URL> -o <outputfile>
    ```
*   **Exemple** :

    ```bash
    nikto -h http://example.com -o results.txt
    ```
* **Explication** :
  * `-o` : Enregistre les résultats dans un fichier.

***

### 🔍 Étape 3 : Options Avancées

***

#### 1. Spécifier un Port

*   **Commande** :

    ```bash
    nikto -h <URL> -p <port>
    ```
*   **Exemple** :

    ```bash
    nikto -h http://example.com -p 8080
    ```
* **Explication** :
  * `-p` : Spécifie un port particulier à scanner.

***

#### 2. Forcer une Connexion SSL/TLS

*   **Commande** :

    ```bash
    nikto -h <URL> -ssl
    ```
*   **Exemple** :

    ```bash
    nikto -h https://example.com -ssl
    ```
* **Explication** :
  * Forcer l'utilisation du protocole HTTPS pour le scan.

***

#### 3. Utiliser un Proxy

*   **Commande** :

    ```bash
    nikto -h <URL> -useproxy <proxy>
    ```
*   **Exemple** :

    ```bash
    nikto -h http://example.com -useproxy http://127.0.0.1:8080
    ```
* **Explication** :
  * `-useproxy` : Acheminer le trafic via un proxy, utile pour masquer l'origine.

***

#### 4. Limiter les Tests à des Plugins Spécifiques

*   **Commande** :

    ```bash
    nikto -h <URL> -Tuning <options>
    ```
*   **Exemple** :

    ```bash
    nikto -h http://example.com -Tuning 123
    ```
* **Explication** :
  * `-Tuning` : Limite les tests à certains types de vulnérabilités.
  * Les options disponibles :
    * `1` : Tests de fichiers dangereux.
    * `2` : Tests d'injections CGI.
    * `3` : Tests de fichiers intéressants.

***

### 📋 Étape 4 : Exemples de Scénarios

***

#### 1. Scan Complet avec Résultats Sauvegardés

*   **Commande** :

    ```bash
    nikto -h http://example.com -o results.txt -v
    ```
* **Explication** :
  * Effectue un scan détaillé et enregistre les résultats dans `results.txt`.

***

#### 2. Scanner un Serveur sur un Port Non Standard

*   **Commande** :

    ```bash
    nikto -h http://example.com -p 8080
    ```
* **Explication** :
  * Scanne le serveur web sur le port 8080.

***

#### 3. Scanner via HTTPS avec un Proxy

*   **Commande** :

    ```bash
    nikto -h https://example.com -useproxy http://127.0.0.1:8080
    ```
* **Explication** :
  * Force le protocole HTTPS et redirige le trafic via un proxy local.

***

#### 4. Scanner en Excluant des Chemins Sensibles

*   **Commande** :

    ```bash
    nikto -h http://example.com -x /admin,/config
    ```
* **Explication** :
  * Exclut `/admin` et `/config` du scan pour éviter de surcharger ces sections.

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations

* Scannez uniquement des serveurs avec une autorisation légale.
* Documentez vos activités pour éviter tout malentendu.

#### 2. Limiter l’Impact sur le Serveur

* Ajustez les paramètres pour éviter de surcharger la cible :
  * Réduisez la vitesse du scan si nécessaire.
  * Excluez les chemins inutiles.

#### 3. Analyser les Résultats avec Soin

* Examinez les résultats pour identifier :
  * Des versions obsolètes de logiciels.
  * Des fichiers exposés non intentionnellement.
  * Des configurations incorrectes.

#### 4. Utiliser avec des Outils Complémentaires

* Combinez Nikto avec d'autres outils comme **Nmap** pour une analyse plus complète :
  * Utilisez Nmap pour identifier les ports ouverts et Nikto pour analyser les services web spécifiques.
