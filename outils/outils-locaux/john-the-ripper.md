# John The Ripper

## John the Ripper - Guide Complet pour le Craquage de Mots de Passe

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### Introduction

**John the Ripper** (ou simplement **John**) est un outil de craquage de mots de passe extrêmement populaire et flexible. Il est utilisé pour tester la robustesse des mots de passe dans divers environnements et supporte une large gamme de formats de hachage, notamment **MD5**, **SHA-1**, **bcrypt**, **NTLM**, et bien d'autres.

#### Points forts :

* Support de nombreux formats de hachage.
* Inclusion d'utilitaires comme _`ssh2john`_ et _`gpg2john`_ pour convertir des formats spécifiques.
* Capacité à utiliser des attaques par dictionnaire, force brute, et règles avancées.

***

### 🚀 Étape 1 : Installation de John the Ripper

***

#### Installation sur Linux (Debian/Ubuntu)

**1. Installation via les dépôts**

*   **Commande** :

    ```bash
    sudo apt update
    sudo apt install john
    ```
* **Explication** :
  * Installe une version précompilée de John the Ripper.

**2. Installation depuis les sources**

Pour la dernière version de John, suivez ces étapes :

1.  **Installer les dépendances** :

    ```bash
    sudo apt install build-essential libssl-dev libgmp-dev
    ```
2.  **Cloner le dépôt GitHub** :

    ```bash
    git clone https://github.com/openwall/john.git
    ```
3.  **Compiler John** :

    ```bash
    cd john/src
    ./configure && make
    ```
4.  **Installer John** :

    ```bash
    bashCopier le codesudo make install
    ```
5.  **Vérifiez l’installation** :

    ```bash
    john --version
    ```

***

#### Installation sur macOS

1.  **Installer Homebrew** (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2.  **Installer John the Ripper** :

    ```bash
    brew install john
    ```
3.  **Vérifier l’installation** :

    ```bash
    john --version
    ```

***

#### Installation sur Windows

1. **Téléchargez la version Windows** depuis le site officiel :
   * https://www.openwall.com/john/.
2. **Décompressez l'archive ZIP** dans un répertoire accessible.
3. Ajoutez le chemin à la variable **PATH** pour l'exécuter depuis n'importe quel dossier.
4.  **Testez l’installation** :

    ```
    john --version
    ```

### 🛠️ Étape 2 : Fonctionnalités de Base

***

#### 1. Générer un Hash à partir d’un Mot de Passe

*   **Commande** :

    ```bash
    echo "password123" | john --stdin --format=raw-md5
    ```
* **Explication** :
  * Génère un hachage MD5 du mot de passe `password123`.

***

#### 2. Craquer un Hachage avec une Liste de Mots

*   **Commande** :

    ```bash
    john --wordlist=/path/to/wordlist.txt hashes.txt
    ```
* **Explication** :
  * `--wordlist` : Spécifie le fichier contenant les mots de passe à tester.
  * `hashes.txt` : Contient les hachages à craquer.

***

#### 3. Craquer un Hachage avec une Attaque par Force Brute

*   **Commande** :

    ```bash
    john --incremental hashes.txt
    ```
* **Explication** :
  * `--incremental` : Lance une attaque par force brute en testant toutes les combinaisons possibles.

***

### 🔍 Étape 3 : Utilitaires \*2john pour Préparer les Hachages

John inclut plusieurs utilitaires qui transforment des formats cryptés en un format compatible.

***

#### 1. Clés SSH (ssh2john)

*   **Commande** :

    ```bash
    ssh2john id_rsa > id_rsa.hash
    ```
* **Explication** :
  * Convertit une clé privée SSH en un format que John peut craquer.

***

#### 2. Clés GPG (gpg2john)

*   **Commande** :

    ```bash
    gpg2john private.key > private.key.hash
    ```
* **Explication** :
  * Prépare un fichier de clé privée GPG pour le craquage.

***

#### 3. Archives ZIP (zip2john)

*   **Commande** :

    ```bash
    zip2john archive.zip > archive.hash
    ```
* **Explication** :
  * Transforme une archive ZIP protégée en un format que John peut traiter.

***

#### 4. Archives RAR (rar2john)

*   **Commande** :

    ```bash
    rar2john archive.rar > archive.hash
    ```
* **Explication** :
  * Convertit une archive RAR en un format compatible.

***

### 📋 Étape 4 : Options Avancées

***

#### 1. Utiliser des Règles pour Améliorer une Attaque

*   **Commande** :

    ```bash
    john --wordlist=/path/to/wordlist.txt --rules hashes.txt
    ```
* **Explication** :
  * Applique des règles pour transformer les mots de passe de la liste (par exemple, ajout de chiffres ou de caractères spéciaux).

***

#### 2. Cibler un Type de Hachage Spécifique

*   **Commande** :

    ```bash
    john --format=raw-md5 hashes.txt
    ```
* **Explication** :
  * `--format` : Définit le type de hachage. Exemple : `raw-md5`, `bcrypt`, `sha1crypt`, etc.

> 💡 **Astuce** : Consultez la liste des formats pris en charge avec :

```bash
john --list=formats
```

***

#### 3. Reprendre une Session Interrompue

*   **Commande** :

    ```bash
    john --restore
    ```
* **Explication** :
  * Permet de reprendre une session interrompue.

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations légales** :
   * L’utilisation de John sans autorisation peut être illégale. Assurez-vous de travailler dans un cadre autorisé.
2. **Utilisez des wordlists pertinentes** :
   * Les listes comme `rockyou.txt` ou celles disponibles dans [SecLists](https://github.com/danielmiessler/SecLists) sont souvent très efficaces.
3. **Sauvegardez vos sessions** :
   * Utilisez `--session` pour sauvegarder votre progression et éviter de recommencer à zéro.
4. **Surveillez les performances** :
   * John peut consommer beaucoup de ressources. Surveillez l’utilisation de la mémoire et du processeur.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
