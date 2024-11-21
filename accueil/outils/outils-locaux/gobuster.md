# Gobuster

## Gobuster - Guide Complet pour la Découverte de Répertoires, Fichiers et Sous-Domaines

***

### Introduction

**Gobuster** est un outil rapide et puissant conçu pour le brute-forcing de :

* Répertoires et fichiers cachés sur des serveurs web.
* Sous-domaines associés à un domaine.
* Buckets Amazon S3 ou des URI spécifiques.

Contrairement à d'autres outils similaires, Gobuster n'analyse pas un serveur via l'exploration traditionnelle. Au lieu de cela, il utilise une méthode basée sur des listes de mots, ce qui le rend extrêmement rapide et efficace.

***

### 🚀 Étape 1 : Installation de Gobuster

***

#### Installation sur Linux (Debian/Ubuntu)

1.  **Mettez à jour vos paquets** :

    ```bash
    sudo apt update
    ```
2.  **Installez Gobuster** :

    ```bash
    sudo apt install gobuster
    ```

    * **Explication** : Cette commande installe Gobuster depuis les dépôts officiels.
3.  **Vérifiez l’installation** :

    ```bash
    gobuster --help
    ```

    * Si cette commande affiche les options d’utilisation, l’installation est réussie.

***

#### Installation depuis les sources (pour les versions plus récentes)

Si votre dépôt contient une version obsolète, vous pouvez compiler Gobuster à partir des sources :

1.  **Installez Golang** (si non installé) :

    ```bash
    sudo apt install golang
    ```
2.  **Téléchargez le code source de Gobuster** :

    ```bash
    git clone https://github.com/OJ/gobuster.git
    ```
3.  **Compilez et installez Gobuster** :

    ```bash
    cd gobuster
    go build
    ```

    * Cela génère un exécutable nommé **`gobuster`** dans le répertoire.
4.  **Déplacez l’exécutable pour une utilisation globale** :

    ```bash
    sudo mv gobuster /usr/local/bin/
    ```

***

#### Installation sur macOS

1.  **Installez Homebrew** (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2.  **Installez Gobuster** :

    ```bash
    brew install gobuster
    ```
3.  **Vérifiez l’installation** :

    ```bash
    gobuster --help
    ```

***

#### Installation sur Windows

1. **Téléchargez l’exécutable** depuis la [page des releases GitHub](https://github.com/OJ/gobuster/releases).
2. **Extrayez l’archive ZIP** et placez l’exécutable dans un répertoire de votre choix.
3. Ajoutez ce répertoire à votre **PATH** système :
   * Accédez à **Paramètres > Système > Paramètres système avancés > Variables d’environnement**.
   * Modifiez la variable **PATH** pour inclure le répertoire contenant Gobuster.
4.  **Testez l’installation** :

    ```bash
    gobuster --help
    ```

***

### 🚀 Étape 2 : Utilisation de Base de Gobuster

***

#### 1. Découverte de Répertoires et de Fichiers Cachés

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt
    ```
* **Explication** :
  * `dir` : Mode de découverte pour les répertoires et fichiers.
  * `-u` : Spécifie l’URL cible.
  * `-w` : Spécifie le chemin de la liste de mots.

***

#### 2. Recherche de Sous-Domaines

*   **Commande** :

    ```bash
    gobuster dns -d example.com -w /path/to/subdomains.txt
    ```
* **Explication** :
  * `dns` : Mode de découverte pour les sous-domaines.
  * `-d` : Spécifie le domaine cible.
  * `-w` : Chemin de la liste de mots contenant les noms de sous-domaines possibles.

***

#### 3. Identification de Fichiers avec Extensions

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -x php,html
    ```
* **Explication** :
  * `-x` : Ajoute des extensions spécifiques à tester (par exemple : `.php`, `.html`).

***

#### 4. Enregistrer les Résultats

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -o results.txt
    ```
* **Explication** :
  * `-o` : Sauvegarde les résultats dans le fichier spécifié (`results.txt`).

***

### 🔍 Étape 3 : Options Avancées et Optimisation

***

#### 1. Utiliser un Proxy pour le Scan

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -p http://127.0.0.1:8080
    ```
* **Explication** :
  * `-p` : Acheminer le trafic via un proxy (ex. : Burp Suite).

***

#### 2. Configurer le Nombre de Threads

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -t 50
    ```
* **Explication** :
  * `-t` : Définit le nombre de threads (par défaut : 10). Une valeur plus élevée augmente la vitesse mais consomme plus de ressources.

***

#### 3. Filtrer les Codes de Statut HTTP

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -s 200,204,301,302
    ```
* **Explication** :
  * `-s` : Filtre les réponses pour inclure uniquement les codes de statut spécifiés.

***

#### 4. Ajouter un Délai entre les Requêtes

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt --delay 200ms
    ```
* **Explication** :
  * `--delay` : Ajoute un délai de 200ms entre les requêtes pour réduire l’impact sur le serveur cible.

***

### 📋 Étape 4 : Exemples de Scénarios Pratiques

***

#### 1. Découverte de Répertoires Cachés

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt
    ```
* **Explication** :
  * Permet de découvrir des répertoires non listés sur le serveur.

***

#### 2. Identifier des Fichiers Sensibles

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -x bak,log,zip
    ```
* **Explication** :
  * Recherche des fichiers associés à des sauvegardes (`.bak`), journaux (`.log`) ou archives (`.zip`).

***

#### 3. Découverte de Sous-Domaines

*   **Commande** :

    ```bash
    gobuster dns -d example.com -w /path/to/subdomains.txt
    ```
* **Explication** :
  * Identifie des sous-domaines associés au domaine cible.

***

#### 4. Audit de Sécurité Complet

*   **Commande** :

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -x php,html,js -s 200,403 --delay 100ms
    ```
* **Explication** :
  * Recherche des fichiers et répertoires spécifiques en filtrant les codes de statut et en ajoutant un délai pour limiter l’impact.

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations** :
   * Toujours tester avec la permission du propriétaire du serveur pour éviter des implications légales.
2. **Limitez l’impact** :
   * Utilisez des options comme `--delay` pour réduire la charge sur le serveur cible.
3. **Analysez les résultats** :
   * Examinez soigneusement les réponses pour identifier des ressources critiques ou mal configurées.
4. **Associez Gobuster avec d'autres outils** :
   * Combinez Gobuster avec des outils comme **Nmap** ou **Burp Suite** pour enrichir vos découvertes.
