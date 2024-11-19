# Burp Suite

#### Introduction

Burp Suite est un ensemble d'outils pour la sécurité des applications web, comprenant un proxy d'interception, un scanner de vulnérabilités, et divers outils pour faciliter les tests de sécurité des applications web.

#### Installation de Burp Suite

**Sous Linux**

1. **Télécharger Burp Suite Community Edition** depuis le [site officiel](https://portswigger.net/burp/communitydownload).
2.  **Rendre le fichier exécutable et lancer Burp Suite** :

    ```bash
    chmod +x burpsuite_community_v2022.1.3.jar
    java -jar burpsuite_community_v2022.1.3.jar
    ```

    * **Explication** :
      * `chmod +x` : Rend le fichier JAR exécutable.
      * `java -jar` : Lance Burp Suite en utilisant l'interpréteur Java.

**Sous Windows**

1. **Télécharger Burp Suite Community Edition** depuis le [site officiel](https://portswigger.net/burp/communitydownload).
2. **Exécuter le fichier d'installation** et suivre les instructions pour l'installation.
   * **Explication** : Installe Burp Suite en suivant les instructions de l'assistant d'installation.

#### Configuration Initiale

**Configurer le Proxy dans Burp Suite**

1. **Lancer Burp Suite**.
2. **Naviguer vers l'onglet "Proxy" > "Options"**.
3. **Vérifier que le proxy écoute sur le port 8080 par défaut** (ou configurer un autre port si nécessaire).
   * **Explication** : Configure le proxy pour intercepter le trafic web.

**Configurer le Proxy de votre navigateur**

1. **Ouvrir les paramètres de proxy de votre navigateur**.
2.  **Configurer le proxy pour utiliser 127.0.0.1 (localhost) et le port 8080**.

    * **Explication** : Redirige le trafic web du navigateur via Burp Suite.



#### Fonctionnalités Principales

**Proxy**

1.  **Intercept** : Permet de capturer et de modifier les requêtes HTTP/HTTPS entre le navigateur et le serveur.

    * **Activer/Désactiver l'interception** : Ouvrir l'onglet "Proxy" > "Intercept" et activer/désactiver l'interception selon vos besoins.
    * **Modifier les requêtes/réponses** : Après interception, vous pouvez modifier les requêtes et les réponses avant qu'elles n'atteignent leur destination.


2.  **HTTP History** : Affiche l'historique des requêtes HTTP/HTTPS capturées.

    * **Accéder à HTTP History** : Ouvrir l'onglet "Proxy" > "HTTP History".
    * **Analyser les requêtes** : Permet d'analyser les requêtes envoyées et reçues pour trouver des vulnérabilités.



**Scanner**

1.  **Activer le Scanner (Pro Edition)**

    * **Ouvrir l'onglet "Scanner"** (disponible uniquement dans la version Pro).
    * **Lancer une analyse active** : Ajouter un site à scanner et configurer les options de scan.
    * **Analyser les résultats** : Examiner les vulnérabilités détectées, telles que les injections SQL, les failles XSS, etc.



**Intruder**

1.  **Configurer une Attaque**

    * **Ouvrir l'onglet "Intruder"**.
    * **Ajouter une requête à attaquer** : Envoyer une requête via l'onglet "Proxy" > "HTTP History" > cliquer sur "Send to Intruder".
    * **Définir des Positions** : Définir les positions dans la requête où les payloads doivent être injectés.
    * **Choisir des Payloads** : Sélectionner les types de payloads (liste de mots de passe, valeurs aléatoires, etc.).
    * **Lancer l'attaque** : Cliquer sur "Start Attack" pour commencer l'attaque.


2.  **Analyser les Résultats**

    * **Examiner les réponses** : Vérifiez les réponses des serveurs pour identifier des failles potentielles.



**Repeater**

1.  **Tester des Requêtes Manuellement**

    * **Ouvrir l'onglet "Repeater"**.
    * **Envoyer une requête à Repeater** : Cliquer sur "Send to Repeater" depuis "Proxy" > "HTTP History".
    * **Modifier et renvoyer la requête** : Modifier la requête et envoyer plusieurs fois pour tester des réponses différentes.


2.  **Analyser les Réponses**

    * **Examinez les réponses** pour détecter des comportements inhabituels ou des vulnérabilités.



**Decoder**

1.  **Décoder et Encoder des Données**

    * **Ouvrir l'onglet "Decoder"**.
    * **Copier les données à décoder** : Coller les données encodées dans le champ approprié.
    * **Décoder ou encoder les données** : Utiliser les fonctions de décodage/encodage pour analyser les données.


2.  **Analyser les Données Décodées**

    * **Examiner les données** pour comprendre la structure des informations échangées.



#### Exemples de Scénarios

**Intercepter et Modifier une Requête HTTP**

1. **Configurer Burp Suite pour intercepter les requêtes**.
2. **Naviguer sur une application web et capturer une requête intéressante**.
3.  **Modifier les paramètres de la requête via l'onglet "Intercept" et observer la réponse**.



**Scanner un Site Web pour les Vulnérabilités (Pro Edition)**

1. **Ajouter un site à l'outil de scanner**.
2. **Configurer les paramètres de scan pour spécifier les types de vulnérabilités à rechercher**.
3.  **Analyser les résultats et identifier les vulnérabilités potentielles**.



**Utiliser Intruder pour une Attaque de Force Brute**

1. **Configurer une attaque de force brute sur un formulaire de connexion**.
2. **Définir les positions pour les payloads dans la requête de connexion**.
3.  **Exécuter l'attaque et analyser les réponses pour identifier les credentials valides**.



#### Discrétion et Bonnes Pratiques

**Limiter la Vitesse des Attaques**

1. **Configurer des délais dans les attaques** pour éviter de surcharger les serveurs et de déclencher des alertes.
2.  **Utiliser des proxies ou des VPN pour masquer l'origine des tests**, si nécessaire.



**Obtenir les Autorisations**

1. **Assurez-vous toujours d'avoir les permissions nécessaires** pour tester la sécurité des applications web.
2.  **Éviter les tests non autorisés** pour éviter des implications légales et éthiques.



**Surveiller les Réactions du Serveur**

1. **Observer les logs et les alertes générés par les applications web** pour ajuster les tests en conséquence.
2.  **Analyser les réponses des serveurs** pour éviter de provoquer des dénis de service ou des perturbations.

