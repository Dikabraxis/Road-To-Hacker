# Gobuster

**Introduction**\
Gobuster est un outil de brute force efficace pour découvrir des répertoires, des fichiers cachés, et des sous-domaines associés à un domaine. Il utilise des listes de mots pour tester différentes routes et noms sur un serveur web.

**Installation de Gobuster**

*   **Sous Linux** :

    ```bash
    sudo apt install gobuster
    ```

    **Explication** : Installe Gobuster à partir des dépôts de votre distribution Linux.
* **Utilisation de Base**

1.  **Brute Force des Répertoires et Fichiers**

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt
    ```

    **Explication** : Cherche des répertoires et des fichiers cachés sur le serveur web en utilisant un dictionnaire de mots pour tester différentes routes.\

2.  **Brute Force des Sous-domaines**

    ```bash
    gobuster dns -d example.com -w /path/to/subdomains.txt
    ```

    **Explication** : Cherche des sous-domaines associés à un domaine cible en utilisant une liste de sous-domaines possibles.\


**Options Avancées**

1.  **Utiliser des Proxy**

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -p http://proxy:port
    ```

    **Explication** : Configure l’utilisation d’un proxy pour acheminer le trafic de brute force à travers celui-ci, ce qui peut aider à masquer l’origine du scan.\

2.  **Configurer la Temporisation et le Nombre de Threads**

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -t 50 -s 200,204,301,302,307,403
    ```

    **Explication** : Ajuste le nombre de threads (`-t`) et les codes de statut HTTP à rechercher (`-s`), ce qui peut améliorer les performances du scan.\


**Exemples de Recherche**

1.  **Découverte des Répertoires Cachés**

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt
    ```

    **Explication** : Permet de découvrir des répertoires non listés sur le serveur web en testant des chemins possibles.\

2.  **Identification des Fichiers Cachés**

    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -x php,html
    ```

    **Explication** : Cherche des fichiers spécifiques en ajoutant des extensions à la liste des mots testés.\
