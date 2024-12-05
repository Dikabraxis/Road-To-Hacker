# Wapiti

## Wapiti - Guide Complet

***

### Introduction

**Wapiti** est un scanner de sécurité web open-source qui analyse les applications web pour détecter des vulnérabilités telles que les injections SQL, les Cross-Site Scripting (XSS), et bien d'autres. Il explore le site en suivant les liens et en testant les paramètres des URL, des formulaires, et des cookies.

***

### 🚀 Étape 1 : Installation de Wapiti

***

#### 1. Installation des Dépendances

Avant d'installer Wapiti, assurez-vous que Python3 et pip3 sont disponibles sur votre machine.

```bash
sudo apt update
sudo apt install python3 python3-pip
```

* **Explications** :
  * `sudo apt update` : Met à jour la liste des paquets disponibles.
  * `sudo apt install python3 python3-pip` : Installe Python3 et son gestionnaire de paquets pip3.

***

#### 2. Installation de Wapiti via pip

Installez Wapiti avec pip3 :

```bash
pip3 install wapiti3
```

* **Explication** :
  * `pip3 install wapiti3` : Télécharge et installe Wapiti depuis le Python Package Index.

***

#### 3. Vérification de l'Installation

Pour confirmer que Wapiti est installé correctement, exécutez :

```bash
wapiti --help
```

* **Résultat attendu** : Une liste des commandes et options disponibles.

***

### 🛠️ Étape 2 : Commandes de Base

***

#### 1. Scanner un Site Web

Pour effectuer un scan de base sur une application web :

```bash
wapiti -u http://example.com
```

* **Explications** :
  * `-u` : Spécifie l'URL cible.
  * `http://example.com` : L'application web à scanner.

***

#### 2. Générer un Rapport

Pour générer un rapport au format HTML après le scan :

```bash
wapiti -u http://example.com -f html -o rapport.html
```

* **Explications** :
  * `-f html` : Définit le format du rapport (HTML dans cet exemple).
  * `-o rapport.html` : Spécifie le fichier de sortie pour le rapport.

***

#### 3. Limiter la Profondeur d’Exploration

Pour restreindre la profondeur d’exploration lors du scan :

```bash
wapiti -u http://example.com --depth 2
```

* **Explications** :
  * `--depth 2` : Limite l'exploration des liens à deux niveaux.

***

### 🔍 Étape 3 : Options Avancées

***

#### 1. Utiliser un Proxy

Pour rediriger le trafic via un proxy (par exemple, Burp Suite) :

```bash
wapiti -u http://example.com --proxy http://localhost:8080
```

* **Explications** :
  * `--proxy` : Spécifie un serveur proxy.

***

#### 2. Configurer un User-Agent et des Cookies

Pour personnaliser le User-Agent ou inclure des cookies dans les requêtes :

```bash
wapiti -u http://example.com --user-agent "Mozilla/5.0" --cookies "cookie1=value1; cookie2=value2"
```

* **Explications** :
  * `--user-agent` : Définit l’en-tête User-Agent envoyé avec les requêtes.
  * `--cookies` : Permet d’inclure des cookies pour accéder à des zones protégées.

***

#### 3. Exclure des Paramètres d’URL

Pour exclure certains paramètres spécifiques des tests :

```bash
wapiti -u http://example.com --ignore-parameters "param1,param2"
```

* **Explication** :
  * `--ignore-parameters` : Ignore les paramètres spécifiés lors des tests de vulnérabilités.

***

#### 4. Spécifier les Types de Vulnérabilités à Tester

Pour limiter les tests à certains types de vulnérabilités :

```bash
wapiti -u http://example.com --attack sql,xss
```

* **Explications** :
  * `--attack` : Spécifie les vulnérabilités à tester (par exemple, SQL Injection ou XSS).

***

### 📋 Étape 4 : Exemples de Commandes

***

#### Exemple 1 : Scanner un Site avec un Rapport HTML

Pour scanner un site et générer un rapport détaillé en HTML :

```bash
wapiti -u http://example.com -f html -o rapport.html
```

***

#### Exemple 2 : Scanner avec un Proxy et une Profondeur Limitée

Pour acheminer le trafic via un proxy et limiter l’exploration à 2 niveaux :

```bash
wapiti -u http://example.com --proxy http://localhost:8080 --depth 2
```

***

#### Exemple 3 : Tester des Vulnérabilités XSS et SQL Uniquement

Pour limiter les tests aux injections SQL et XSS :

```bash
wapiti -u http://example.com --attack sql,xss
```

***

#### Exemple 4 : Exclure des Paramètres d’URL

Pour ignorer certains paramètres d’URL lors du scan :

```bash
wapiti -u http://example.com --ignore-parameters "session_id,token"
```

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations

* **Important** : N’exécutez jamais de scans sans l’autorisation explicite du propriétaire du site.
* **Respectez les lois** : Les tests non autorisés peuvent entraîner des conséquences juridiques.

#### 2. Minimiser l’Impact

* **Limiter les tests** : Configurez les scans pour éviter de surcharger le serveur ou d'attirer l'attention.
* **Utiliser les options avancées** : Filtrez les paramètres inutiles et testez uniquement les vulnérabilités pertinentes.

#### 3. Analyser les Résultats

* **Examiner en détail** : Lisez attentivement les rapports pour identifier les vulnérabilités critiques.
* **Corrélation avec d’autres outils** : Combinez les résultats de Wapiti avec des outils comme **Nmap**, **Nikto**, ou **Burp Suite**.

***

### Conclusion

**Wapiti** est un outil essentiel pour les professionnels de la cybersécurité cherchant à analyser les applications web. Grâce à sa flexibilité et à ses nombreuses options, il permet une reconnaissance efficace et des tests ciblés pour détecter les vulnérabilités potentielles.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
