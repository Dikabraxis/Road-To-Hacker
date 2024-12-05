# Dirb

## DIRB - Outil de Fuzzing Web pour la Découverte de Répertoires et Fichiers Cachés

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### Introduction

**DIRB** (Directory Buster) est un outil puissant conçu pour rechercher des répertoires et fichiers cachés sur un serveur web. En utilisant des listes de mots (wordlists), il permet d'identifier des ressources qui ne sont pas directement référencées dans les pages visibles.

#### Utilisations principales :

* **Découverte de contenus cachés** : Répertoires administratifs, fichiers de configuration, sauvegardes oubliées, etc.
* **Audit de sécurité** : Identifier des failles potentielles comme des permissions faibles ou des ressources accessibles publiquement.

***

### 🚀 Installation de DIRB

#### Installation sur Linux

**DIRB** est préinstallé sur des distributions orientées sécurité comme **Kali Linux**, mais vous pouvez facilement l’installer sur d’autres distributions basées sur Debian.

1.  **Mettre à jour les paquets** :

    ```bash
    sudo apt update
    ```

    * **Explication** : Cela garantit que vous téléchargez les dernières versions disponibles.
2.  **Installer DIRB** :

    ```bash
    sudo apt install dirb
    ```

    * **Explication** : Installe DIRB via le gestionnaire de paquets `apt`.
3.  **Vérifier l'installation** :

    ```bash
    dirb --help
    ```

    * **Explication** : Affiche les options et aide de DIRB pour s'assurer qu'il est correctement installé.

***

#### Installation sur Windows

DIRB n'est pas nativement compatible avec Windows, mais il peut être utilisé via des environnements comme **Cygwin** ou **Windows Subsystem for Linux (WSL)**.

**Étapes pour utiliser DIRB avec WSL :**

1. **Installer WSL** :
   * Activez la fonctionnalité WSL via **Paramètres > Fonctionnalités Windows**.
   * Téléchargez une distribution Linux (par exemple, **Ubuntu**) depuis le **Microsoft Store**.
2. **Installer DIRB dans WSL** :
   * Lancez WSL et suivez les étapes pour Linux ci-dessus (mise à jour et installation).

***

### 🛠️ Utilisation de Base de DIRB

#### 1. Découverte de Répertoires et de Fichiers (Scan de Base)

*   **Commande** :

    ```bash
    dirb http://example.com
    ```
* **Explication** :
  * Lance un scan basique en utilisant les wordlists par défaut de DIRB pour explorer les répertoires et fichiers sur le serveur cible.

> ⚠️ **Attention** : Ce type de scan peut générer beaucoup de trafic, ce qui le rend facilement détectable par les systèmes IDS/IPS (systèmes de détection/prévention d'intrusions).

***

#### 2. Utilisation d’une Wordlist Personnalisée

*   **Commande** :

    ```bash
    dirb http://example.com /path/to/custom_wordlist
    ```
* **Explication** :
  * Spécifie une liste de mots personnalisée à utiliser pour tester des chemins spécifiques.

> 💡 **Astuce** : Utilisez des listes de mots spécialisées comme celles de **SecLists** ([GitHub SecLists](https://github.com/danielmiessler/SecLists)).

***

#### 3. Enregistrement des Résultats dans un Fichier

*   **Commande** :

    ```bash
    dirb http://example.com -o results.txt
    ```
* **Explication** :
  * Utilise l'option `-o` pour enregistrer les résultats du scan dans un fichier (`results.txt`).

***

### 🔍 Options Avancées

#### 1. Ignorer les Codes de Statut Indésirables

*   **Commande** :

    ```bash
    dirb http://example.com -N 404
    ```
* **Explication** :
  * Exclut les réponses HTTP ayant le statut `404` (non trouvé), ce qui réduit le bruit dans les résultats.

***

#### 2. Tester des Extensions de Fichiers Spécifiques

*   **Commande** :

    ```bash
    dirb http://example.com -X .php,.html
    ```
* **Explication** :
  * Cible uniquement les chemins ayant les extensions spécifiées (ex. : `.php`, `.html`).

> 💡 **Astuce** : Utilisez cette option pour rechercher des fichiers critiques comme `config.php` ou `admin.html`.

***

#### 3. Utiliser un Délai entre les Requêtes

*   **Commande** :

    ```bash
    dirb http://example.com -z 200ms
    ```
* **Explication** :
  * Ajoute un délai de 200ms entre les requêtes pour réduire l’impact sur le serveur et éviter d’attirer l’attention.

***

#### 4. Scanner via un Proxy

*   **Commande** :

    ```bash
    dirb http://example.com -p http://127.0.0.1:8080
    ```
* **Explication** :
  * Achemine les requêtes via un proxy (ex. : Burp Suite) pour intercepter ou anonymiser le trafic.

***

### 📋 Exemples de Scénarios Pratiques

#### 1. Découverte de Panneaux d'Administration Cachés

*   **Commande** :

    ```bash
    dirb http://example.com /usr/share/dirb/wordlists/common.txt -X .php
    ```
* **Explication** :
  * Cible les fichiers PHP, souvent utilisés pour des interfaces d’administration (ex. : `admin.php`, `login.php`).

***

#### 2. Audit de Sécurité d'une Application Web

*   **Commande** :

    ```bash
    dirb http://example.com /path/to/security_audit_wordlist -N 200-299
    ```
* **Explication** :
  * Concentre le scan sur les réponses ayant des codes de statut compris entre `200` et `299` (codes de succès).

***

#### 3. Découverte de Sauvegardes ou Fichiers Sensibles

*   **Commande** :

    ```bash
    dirb http://example.com -X .bak,.old,.txt
    ```
* **Explication** :
  * Cible des extensions spécifiques souvent utilisées pour des fichiers sensibles laissés accidentellement accessibles (ex. : `config.bak`, `data.old`).

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations** :
   * Avant d'utiliser DIRB, assurez-vous que vous avez une autorisation légale pour scanner le serveur cible.
2. **Minimisez l’impact** :
   * Utilisez un délai entre les requêtes (`-z`) pour réduire la charge sur le serveur.
   * Évitez d’utiliser de grandes listes de mots sur des serveurs en production.
3. **Analysez les résultats avec soin** :
   * Identifiez les fichiers ou répertoires qui nécessitent une correction immédiate pour sécuriser le système.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
