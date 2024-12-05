# Burp Suite

## Burp Suite - Guide Pas-à-Pas Complet

***

### Introduction

**Burp Suite** est un outil incontournable pour les tests de sécurité des applications web. Il regroupe une série d'outils intégrés permettant de :

* Intercepter et modifier les requêtes HTTP/S.
* Scanner les vulnérabilités des applications web (injections SQL, XSS, etc.).
* Automatiser des attaques (brute-force, fuzzing).
* Décoder et analyser des données.

Les deux versions principales :

1. **Community Edition** : Gratuite, idéale pour apprendre, mais limitée (pas de scanner automatique, fonctionnalités avancées restreintes).
2. **Pro Edition** : Payante, avec des outils supplémentaires comme le Scanner ou la gestion avancée des attaques.

Ce guide détaillé couvre :

1. L'installation et la configuration complète.
2. Une explication pas-à-pas des fonctionnalités.
3. Des scénarios pratiques pour chaque outil.

***

### 🚀 Étape 1 : Installation de Burp Suite

#### Prérequis

1. **Java Runtime Environment (JRE)** :
   * Burp Suite nécessite Java pour fonctionner.
   *   Vérifiez la version installée avec :

       ```bash
       java -version
       ```
   * Si non installé :
     *   **Linux** :

         ```bash
         sudo apt update
         sudo apt install default-jre
         ```
     * **Windows/macOS** : Téléchargez Java depuis [Oracle Java](https://www.oracle.com/java/technologies/javase-downloads.html).

***

#### Installation sur Windows

1. Téléchargez le fichier **`.exe`** depuis le site officiel.
2. Lancez le fichier et suivez les instructions de l'assistant d'installation.
3. Une fois terminé, lancez Burp Suite via le menu **Démarrer**.

***

#### Installation sur macOS

1. Téléchargez le fichier **`.dmg`** depuis PortsWigger.
2. Double-cliquez sur le fichier téléchargé.
3. Glissez l’icône Burp Suite dans le dossier **Applications**.
4. Lancez Burp Suite depuis le **Finder** ou via Spotlight.

***

#### Installation sur Linux

1. Téléchargez le fichier **`.sh`** depuis le site officiel.
2.  Rendez le fichier exécutable :

    ```bash
    chmod +x burpsuite_community_linux_v*.sh
    ```
3.  Exécutez le fichier pour lancer l’installation :

    ```bash
    ./burpsuite_community_linux_v*.sh
    ```
4.  Lancez Burp Suite depuis votre terminal :

    ```bash
    burpsuite
    ```

***

### 🚀 Étape 2 : Configuration du Proxy

Burp Suite agit comme un proxy entre votre navigateur et l'application cible, permettant d’intercepter et de modifier les requêtes HTTP/S.

1. **Configurer le navigateur** :
   * Modifiez les paramètres du proxy de votre navigateur pour utiliser :
     * **Adresse** : `127.0.0.1`
     * **Port** : `8080`.
   * **Firefox** :
     * Allez dans **Paramètres** > **Paramètres réseau** > **Configuration manuelle du proxy**.
     * Entrez les détails ci-dessus.
2. **Importer le certificat HTTPS** :
   * Ouvrez votre navigateur et allez sur : `http://burp`.
   * Téléchargez le certificat CA.
   * Importez-le dans votre navigateur (paramètres de certificat).
   * Cela permettra d’intercepter les requêtes HTTPS.

***

### 🛠️ Fonctionnalités de Burp Suite

***

#### 🛠️ 1. **Proxy** - Intercepter et modifier des requêtes

**Étapes :**

1. Lancez Burp Suite et ouvrez l’onglet **`Proxy`**.
2. Activez **`Intercept`**.
3. Naviguez sur l'application web cible.
4. Burp Suite capturera chaque requête avant qu’elle ne soit envoyée.
5. Modifiez les paramètres (ex. : `user_id=1` → `user_id=2`) et observez la réponse.

> 💡 **Astuce** : Utilisez l'onglet **`HTTP History`** pour analyser les requêtes passées et les envoyer à d'autres outils comme **Repeater** ou **Intruder**.

***

#### 🛠️ 2. **Scanner (Pro Edition)** - Détecter les vulnérabilités

**Étapes :**

1. Ouvrez l'onglet **`Scanner`** (Pro uniquement).
2. **Ajouter un site** :
   * Cliquez sur **`New Scan`** et entrez l'URL de l'application cible.
3. **Configurer les paramètres** :
   * Types de tests (XSS, SQL Injection, etc.).
   * Profondeur de crawl.
4. **Analyser les résultats** :
   * Les vulnérabilités sont classées par gravité.
   * Cliquez sur chaque résultat pour voir les détails et les recommandations.

> ⚠️ **Attention** : Limitez les scans à une zone spécifique de l'application pour éviter de surcharger le serveur.

***

#### 🛠️ 3. **Intruder** - Automatiser les attaques

**Étapes :**

1. **Envoyer une requête à Intruder** :
   * Depuis **`Proxy > HTTP History`**, sélectionnez une requête et cliquez sur **`Send to Intruder`**.
2. **Configurer les positions** :
   * Identifiez les champs à tester (ex. : `username` et `password` dans un formulaire POST).
   * Marquez-les comme variables dans **`Positions`**.
3. **Ajouter des payloads** :
   * Allez dans **`Payloads`** et ajoutez une liste (ex. : mots de passe pour brute-force).
4. **Lancer l’attaque** :
   * Cliquez sur **`Start Attack`** et observez les résultats.

> 💡 **Astuce** : Utilisez des listes de payloads personnalisées comme [SecLists](https://github.com/danielmiessler/SecLists).

***

#### 🛠️ 4. **Repeater** - Tester des requêtes manuellement

**Étapes :**

1. Envoyez une requête depuis **`Proxy > HTTP History`** vers **Repeater**.
2. Modifiez les paramètres (ex. : `id=1` → `id=' OR 1=1 --`).
3. Cliquez sur **`Send`** et examinez les réponses.

> 💡 **Exemple** : Testez les injections SQL ou XSS en manipulant les paramètres.

***

#### 🛠️ 5. **Decoder** - Décoder et encoder des données

**Étapes :**

1. Ouvrez l’onglet **`Decoder`**.
2. Collez des données encodées (Base64, URL, etc.).
3. Cliquez sur **`Decode`** pour les analyser.

***

### 📋 Exemples de Scénarios Pratiques

***

#### 1. **Scanner une application web pour les vulnérabilités**

* Configurez le scanner pour détecter les injections SQL et XSS.
* Analysez les résultats pour identifier les failles.

***

#### 2. **Force brute sur un formulaire de connexion**

1. Configurez **Intruder** sur une requête POST de connexion.
2. Utilisez une liste de mots de passe courants comme payloads.
3. Observez les réponses pour identifier un login valide.

***

#### 3. **Décoder un jeton JWT**

* Utilisez **Decoder** pour décoder un token JWT et analyser son contenu.

### 📖 Bonnes Pratiques

1. **Limiter la vitesse des attaques** :
   * Ajoutez des délais entre les requêtes pour éviter d’être détecté par le serveur cible.
2. **Utiliser un proxy ou un VPN** :
   * Masquez votre adresse IP lors des tests.
3. **Obtenir des autorisations** :
   * Testez uniquement avec des permissions légales pour éviter des conséquences juridiques.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
