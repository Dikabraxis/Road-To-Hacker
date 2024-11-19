# Wapiti

#### Introduction

Wapiti est un scanner de vulnérabilités qui analyse les applications web pour détecter les failles de sécurité telles que les injections SQL, les scripts inter-sites (XSS), les failles de redirection, et bien plus. Il fonctionne en explorant les pages web et en testant les points d'entrée pour identifier les vulnérabilités.

#### Installation de Wapiti

**1. Installation sur Linux**

1.  **Installer les dépendances** :

    ```bash
    sudo apt update
    sudo apt install python3 python3-pip
    ```

    * **Explication** :
      * `sudo apt update` : Met à jour la liste des paquets disponibles.
      * `sudo apt install python3 python3-pip` : Installe Python3 et pip3, le gestionnaire de paquets Python.
2.  **Installer Wapiti via pip** :

    ```bash
    pip3 install wapiti3
    ```

    * **Explication** :
      * `pip3 install wapiti3` : Installe Wapiti via pip3.
3.  **Vérifier l'installation** :

    ```bash
    wapiti --help
    ```

    * **Explication** : Vérifie que Wapiti est installé correctement.

#### Utilisation de Base

**1. Scan d'un Site Web**

**Commandement de base pour scanner un site web** :

```bash
wapiti -u http://example.com
```

* **Explication** :
  * `-u` : Spécifie l'URL du site web à scanner.
  * `http://example.com` : URL de l'application web cible.



**2. Génération d'un Rapport**

**Générer un rapport au format HTML** :

```bash
wapiti -u http://example.com -f html -o rapport.html
```

* **Explication** :
  * `-f html` : Spécifie le format du rapport (HTML dans ce cas).
  * `-o rapport.html` : Spécifie le fichier de sortie pour le rapport.



**3. Limiter la Profondeur du Scan**

**Définir la profondeur maximale du scan** :

```bash
wapiti -u http://example.com --depth 2
```

* **Explication** :
  * `--depth 2` : Limite la profondeur de l'exploration à 2 niveaux de liens.



#### Options Avancées

**1. Utilisation d'un Proxy**

**Configurer un proxy pour le scan** :

```bash
wapiti -u http://example.com --proxy http://localhost:8080
```

* **Explication** :
  * `--proxy` : Permet d'utiliser un serveur proxy pour le scan.



**2. Configurer des Paramètres de Connexion**

**Définir un User-Agent personnalisé et des cookies** :

```bash
wapiti -u http://example.com --user-agent "Mozilla/5.0" --cookies "cookie1=value1; cookie2=value2"
```

* **Explication** :
  * `--user-agent` : Définit le User-Agent utilisé pour les requêtes HTTP.
  * `--cookies` : Spécifie les cookies à utiliser pour accéder à des zones protégées.



**3. Exclure des Paramètres de Scan**

**Exclure certains paramètres d'URL du scan** :

```bash
wapiti -u http://example.com --ignore-parameters "param1,param2"
```

* **Explication** :
  * `--ignore-parameters` : Permet d'exclure des paramètres spécifiques des tests de vulnérabilités.



#### Exemples de Commandes

**1. Scanner un Site Web avec Rapport HTML**

**Commande pour scanner et générer un rapport** :

```bash
wapiti -u http://example.com -f html -o rapport.html
```

**2. Scanner avec Proxy et Profondeur Limité**

**Commande pour scanner avec un proxy et une profondeur maximale de 2** :

```bash
wapiti -u http://example.com --proxy http://localhost:8080 --depth 2
```
