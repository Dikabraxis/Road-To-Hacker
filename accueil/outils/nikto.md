# Nikto

#### Introduction

Nikto est un outil de scan de vulnérabilités pour les serveurs web. Il recherche des problèmes courants tels que des fichiers ou des répertoires vulnérables, des versions de logiciels obsolètes et des configurations de sécurité incorrectes. Nikto est efficace pour une première évaluation de la sécurité des serveurs web.

#### Installation de Nikto

**Installation sur Linux**

1.  **Installer via `apt` (pour les distributions basées sur Debian)**

    ```bash
    sudo apt update
    sudo apt install nikto
    ```
2.  **Installer via `git`**

    ```bash
    git clone https://github.com/sullo/nikto.git
    cd nikto
    ```

#### Commandes de Base

**Scan de Base d'un Serveur Web**

1.  **Effectuer un scan de base sur un serveur web**

    ```bash
    nikto -h <URL>
    ```

    * **Explication** : `-h` spécifie l'URL ou l'adresse IP du serveur web à scanner.



**Scan en Mode Verbose**

1.  **Activer le mode verbose pour des détails supplémentaires**

    ```bash
    nikto -h <URL> -v
    ```

    * **Explication** : `-v` active le mode verbose pour afficher plus de détails sur le scan et les résultats.



**Scan avec une Liste de Mots Personnalisée**

1.  **Utiliser une liste de mots personnalisée pour les tests**

    ```bash
    nikto -h <URL> -w <wordlist>
    ```

    * **Explication** : `-w` spécifie le chemin vers un fichier de liste de mots personnalisé pour les tests.



**Exclusion de Fichiers et Répertoires**

1.  **Exclure certains fichiers et répertoires du scan**

    ```bash
    nikto -h <URL> -x <path>
    ```

    * **Explication** : `-x` permet de spécifier un ou plusieurs chemins à exclure du scan.



**Sauvegarder les Résultats dans un Fichier**

1.  **Enregistrer les résultats du scan dans un fichier**

    ```bash
    nikto -h <URL> -o <outputfile>
    ```

    * **Explication** : `-o` spécifie le chemin vers le fichier de sortie où les résultats du scan seront enregistrés.



#### Exemples de Scénarios

**Scan de Base**

1.  **Scanner un serveur web**

    ```bash
    nikto -h http://example.com
    ```

**Scan Verbose**

1.  **Effectuer un scan détaillé avec des informations supplémentaires**

    ```bash
    nikto -h http://example.com -v
    ```

**Scan avec Liste de Mots**

1.  **Utiliser une liste de mots personnalisée pour le scan**

    ```bash
    nikto -h http://example.com -w /path/to/wordlist.txt
    ```

**Exclusion de Chemins**

1.  **Exclure certains chemins du scan**

    ```bash
    nikto -h http://example.com -x /excluded/path
    ```

**Sauvegarde des Résultats**

1.  **Enregistrer les résultats du scan dans un fichier**

    ```bash
    nikto -h http://example.com -o results.txt
    ```

#### Bonnes Pratiques

1. **Obtenir des Autorisations**
   * **Assurez-vous d'avoir l'autorisation** de scanner le serveur web avant de lancer un scan.
   * **Respectez les lois et les politiques** de sécurité applicables.
2. **Limiter l'Impact**
   * **Configurez le scan pour ne pas surcharger le serveur** en ajustant les options comme la vitesse de scan.
   * **Excluez les chemins non pertinents** pour éviter de générer du bruit inutile.
3. **Analyser les Résultats avec Prudence**
   * **Examinez les résultats** pour identifier les failles et les vulnérabilités potentielles sans générer de faux positifs.
