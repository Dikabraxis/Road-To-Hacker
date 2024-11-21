# Wfuzz

## Wfuzz - Guide Complet

***

### Introduction

**Wfuzz** est un outil de fuzzing polyvalent et flexible utilisé pour découvrir des répertoires, des fichiers cachés, et tester les paramètres d'entrée d'une application web. Il est particulièrement utile dans les phases de reconnaissance et de tests de vulnérabilités, comme les tests de paramètres GET/POST ou les attaques basées sur des mots de passe.

***

### 🚀 Étape 1 : Installation de Wfuzz

***

#### 1. Installation via **apt** (Debian/Ubuntu)

Installez Wfuzz directement depuis les dépôts officiels :

```bash
sudo apt update
sudo apt install wfuzz
```

* **Explications** :
  * `apt update` : Met à jour la liste des paquets disponibles.
  * `apt install wfuzz` : Installe Wfuzz à l’aide du gestionnaire de paquets apt.

***

#### 2. Installation via **pip** (Python)

Pour installer Wfuzz via le Python Package Index :

```bash
pip install wfuzz
```

* **Explication** :
  * Installe Wfuzz et ses dépendances directement en utilisant pip.

***

#### 3. Tester l’Installation

Vérifiez que Wfuzz est correctement installé en exécutant :

```bash
wfuzz -h
```

* **Résultat attendu** : Une liste d’options et d’exemples de commandes disponibles.

***

### 🛠️ Étape 2 : Commandes de Base

***

#### 1. Découverte de Répertoires et de Fichiers Cachés

Pour scanner un site web et découvrir des répertoires ou des fichiers non listés :

```bash
wfuzz -c -w <wordlist> -u <url>/FUZZ
```

*   **Exemple** :

    ```bash
    wfuzz -c -w /usr/share/wordlists/dirb/common.txt -u http://example.com/FUZZ
    ```
* **Explications** :
  * `-c` : Active la sortie colorée pour mieux visualiser les résultats.
  * `-w` : Spécifie la liste de mots (wordlist) utilisée pour le fuzzing.
  * `-u` : Spécifie l'URL cible avec `FUZZ` comme point d'injection.

***

#### 2. Tester des Paramètres GET

Pour injecter des payloads dans des paramètres GET :

```bash
wfuzz -c -w <wordlist> -u <url>?param=FUZZ
```

*   **Exemple** :

    ```bash
    wfuzz -c -w /usr/share/wordlists/common.txt -u http://example.com/page?param=FUZZ
    ```
* **Explication** :
  * Injecte des valeurs dans le paramètre `param` pour identifier des réponses ou des vulnérabilités.

***

#### 3. Tester des Paramètres POST

Pour tester des formulaires ou des points d’entrée utilisant POST :

```bash
wfuzz -c -w <wordlist> -d "username=FUZZ&password=1234" -u <url> -X POST
```

*   **Exemple** :

    ```bash
    wfuzz -c -w /usr/share/wordlists/common.txt -d "username=FUZZ&password=1234" -u http://example.com/login -X POST
    ```
* **Explications** :
  * `-d` : Spécifie les données POST à envoyer.
  * `-X POST` : Définit le type de requête (POST).

***

#### 4. Filtrer les Réponses en Fonction des Codes de Statut

Pour afficher uniquement les réponses avec des codes de statut spécifiques :

```bash
wfuzz -c -w <wordlist> -u <url>/FUZZ -fc <status_codes>
```

*   **Exemple** :

    ```bash
    wfuzz -c -w /usr/share/wordlists/dirb/common.txt -u http://example.com/FUZZ -fc 404
    ```
* **Explications** :
  * `-fc` : Filtre les réponses contenant les codes de statut spécifiés (par exemple, 404 pour ignorer les "Not Found").

***

#### 5. Filtrer les Réponses en Fonction de la Taille

Pour afficher uniquement les réponses avec une taille spécifique :

```bash
wfuzz -c -w <wordlist> -u <url>/FUZZ -fs <size>
```

*   **Exemple** :

    ```bash
    wfuzz -c -w /usr/share/wordlists/dirb/common.txt -u http://example.com/FUZZ -fs 1234
    ```
* **Explications** :
  * `-fs` : Filtre les réponses en fonction de leur taille (en octets).

***

### 🔍 Étape 3 : Scénarios Avancés

***

#### 1. Recherche de Répertoires Cachés

Pour utiliser une liste de mots commune pour découvrir des répertoires cachés :

```bash
wfuzz -c -w /usr/share/wordlists/dirb/common.txt -u http://example.com/FUZZ
```

* **Explication** :
  * Tente de découvrir des répertoires non répertoriés dans `example.com` en testant chaque mot dans la liste de mots.

***

#### 2. Test de Vulnérabilités dans les Paramètres GET

Pour tester des vulnérabilités potentielles dans les paramètres GET :

```bash
wfuzz -c -w /usr/share/wordlists/payloads.txt -u http://example.com/page?input=FUZZ
```

* **Explication** :
  * Injecte des payloads pour identifier des failles comme les injections SQL, les XSS, ou d'autres vulnérabilités.

***

#### 3. Test des Paramètres POST avec des Combinaisons de Noms d’Utilisateur

Pour tester un formulaire de connexion :

```bash
wfuzz -c -w /usr/share/wordlists/usernames.txt -d "username=FUZZ&password=password123" -u http://example.com/login -X POST
```

* **Explication** :
  * Essaie différents noms d’utilisateur avec un mot de passe fixe pour identifier des comptes valides.

***

#### 4. Utiliser un Proxy pour Masquer l’Origine

Pour acheminer le trafic via un proxy (comme Burp Suite) :

```bash
wfuzz -c -w /usr/share/wordlists/dirb/common.txt -u http://example.com/FUZZ --proxy http://127.0.0.1:8080
```

* **Explication** :
  * `--proxy` redirige le trafic via un proxy HTTP pour masquer l'origine des requêtes ou inspecter le trafic.

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations

* **Important** : Avant d'exécuter Wfuzz, assurez-vous d'avoir une autorisation écrite du propriétaire du domaine.
* **Respectez les lois** : Ne pas effectuer de tests non autorisés pour éviter des conséquences légales.

#### 2. Limiter l’Impact

* Utilisez des délais (`--delay`) entre les requêtes pour réduire la charge sur le serveur.
* Configurez le fuzzing pour qu’il cible des zones spécifiques, en évitant de tester inutilement des chemins ou des paramètres non pertinents.

#### 3. Analyser les Résultats avec Soin

* Vérifiez les réponses en détail pour distinguer les résultats significatifs des faux positifs.
* Combinez Wfuzz avec des outils comme **Nmap** ou **Nikto** pour valider vos découvertes.

***

### Conclusion

**Wfuzz** est un outil incroyablement flexible pour le fuzzing, permettant de découvrir des répertoires, des fichiers cachés, et des failles dans les paramètres d'entrée. Grâce à ses nombreuses options et à son intégration facile dans un workflow de pentesting, il est incontournable pour les phases de reconnaissance et de tests de vulnérabilité.
