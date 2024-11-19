# Wfuzz

#### Introduction

Wfuzz est un outil de fuzzing spécialisé dans la découverte de vulnérabilités sur les applications web. Il est utilisé pour tester divers aspects des applications, y compris la découverte de répertoires et de fichiers cachés, ainsi que les tests de paramètres HTTP. Wfuzz est particulièrement utile pour effectuer des attaques par force brute et des tests de pénétration pour identifier des failles de sécurité potentielles. Ce tutoriel détaille l'installation et les commandes de base pour utiliser Wfuzz efficacement sur les systèmes Linux et Windows.

#### Installation de Wfuzz

**Installation sur Linux**

1.  **Installer via `apt` (pour les distributions basées sur Debian)**

    ```bash
    sudo apt update
    sudo apt install wfuzz
    ```
2.  **Installer via `pip` (Python Package Index)**

    ```bash
    pip install wfuzz
    ```

#### Commandes de Base

**Fuzzing de Répertoires et de Fichiers**

1.  **Découverte de répertoires et de fichiers cachés**

    ```bash
    wfuzz -c -w <wordlist> -u <url>/FUZZ
    ```

    * **Explication** : `-w` spécifie le fichier de liste de mots (wordlist) contenant les noms de répertoires et de fichiers à tester. `-u` spécifie l'URL cible avec le mot-clé `FUZZ` comme point d'injection.



**Test de Paramètres HTTP**

1.  **Tester des paramètres GET avec des payloads**

    ```bash
    wfuzz -c -w <wordlist> -u <url>?param=FUZZ
    ```

    * **Explication** : `param=FUZZ` indique où injecter les payloads dans les paramètres GET.


2.  **Tester des paramètres POST**

    ```bash
    wfuzz -c -w <wordlist> -d "param=FUZZ" -u <url> -X POST
    ```

    * **Explication** : `-d` spécifie les données POST à envoyer avec `param=FUZZ` pour injecter les payloads dans les paramètres.



**Analyse des Réponses**

1.  **Afficher les réponses avec des codes de statut spécifiques**

    ```bash
    wfuzz -c -w <wordlist> -u <url>/FUZZ -fc <status_codes>
    ```

    * **Explication** : `-fc` permet de filtrer les réponses en fonction des codes de statut HTTP (par exemple, 200, 403).


2.  **Afficher uniquement les réponses de taille spécifique**

    ```bash
    wfuzz -c -w <wordlist> -u <url>/FUZZ -fs <size>
    ```

    * **Explication** : `-fs` filtre les réponses en fonction de la taille (en octets). Utile pour détecter les réponses spécifiques.



#### Exemples de Scénarios

**Découverte de Répertoires et de Fichiers**

**Tester des répertoires et des fichiers cachés**

```bash
wfuzz -c -w /usr/share/wordlists/dirb/common.txt -u http://example.com/FUZZ
```

* **Explication** : Utilise une liste de mots commune pour tester des répertoires et des fichiers sur le serveur cible.

**Test de Paramètres GET**

**Tester des paramètres GET pour des vulnérabilités**

```bash
wfuzz -c -w /usr/share/wordlists/common.txt -u http://example.com/page?param=FUZZ
```

* **Explication** : Injecte des payloads dans les paramètres GET pour détecter des réponses spécifiques ou des vulnérabilités.

**Test de Paramètres POST**

**Tester des paramètres POST pour des failles**

```bash
wfuzz -c -w /usr/share/wordlists/common.txt -d "username=FUZZ&password=1234" -u http://example.com/login -X POST
```

* **Explication** : Teste des payloads dans les paramètres POST pour identifier des réponses ou des failles potentielles.

#### Bonnes Pratiques

1. **Obtenir des Autorisations**
   * **Assurez-vous toujours** d'avoir les autorisations nécessaires avant de lancer des tests de fuzzing sur un serveur.
   * **Respectez les lois et les politiques** de sécurité applicables.
2. **Limiter l'Impact**
   * **Utilisez des listes de mots de manière ciblée** pour éviter de surcharger le serveur ou de générer des alertes inutiles.
   * **Configurez les délais entre les requêtes** pour réduire la charge sur le serveur.
3. **Analyser les Résultats avec Prudence**
   * **Examinez les réponses** pour identifier les réponses pertinentes sans générer de bruit inutile.
