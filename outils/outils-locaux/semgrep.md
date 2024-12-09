# Semgrep

## **Semgrep - Guide Complet pour l’Analyse Statique de Code**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**Semgrep** est un outil d’analyse statique de code léger, flexible, et facile à utiliser. Il permet de détecter des failles de sécurité, des mauvaises pratiques, et des violations des normes de codage dans divers langages de programmation tels que Python, Java, JavaScript, C, et bien d’autres. Contrairement aux outils traditionnels d’analyse statique, Semgrep utilise une syntaxe de motifs (patterns) inspirée des langages eux-mêmes, ce qui le rend particulièrement intuitif.

**Principales fonctionnalités :**

* Analyse multi-langages et prise en charge des règles personnalisées.
* Vérification des bonnes pratiques DevSecOps.
* Détection de vulnérabilités courantes comme XSS, injection SQL, utilisation de `eval`, etc.
* Compatible avec les pipelines CI/CD pour des analyses automatisées.

***

### **🚀 Étape 1 : Installation de Semgrep**

**1. Installation sur Linux/macOS**

1.  Installez Semgrep avec pip (Python doit être installé) :

    ```bash
    pip install semgrep
    ```
2.  Vérifiez l’installation :

    ```bash
    semgrep --version
    ```

    Cela devrait retourner la version installée.

**2. Installation sur Windows**

1. Téléchargez et installez Python 3 (si non installé).
2.  Installez Semgrep avec pip :

    ```bash
    pip install semgrep
    ```
3. Ajoutez Semgrep au PATH système si nécessaire.

**3. Installation via Docker**

Si vous préférez utiliser Docker :

```bash
docker pull returntocorp/semgrep
```

Pour exécuter des commandes avec Docker :

```bash
docker run --rm -v "$(pwd):/src" returntocorp/semgrep --config=auto /src
```

**4. Mise à Jour de Semgrep**

Pour garder Semgrep à jour :

```bash
pip install --upgrade semgrep
```

***

### **🛠️ Étape 2 : Utilisation de Base de Semgrep**

Semgrep repose sur des règles qui définissent les motifs de code à analyser. Ces règles peuvent être :

* **Prédéfinies :** Issues de la bibliothèque officielle (ex : `python-security`).
* **Personnalisées :** Créées par l'utilisateur pour répondre à des besoins spécifiques.

***

**1. Analyse d’un Fichier avec une Configuration Prédéfinie**

Commande :

```bash
semgrep --config=python-security file.py
```

**Explications :**

* `--config=python-security` : Utilise une configuration officielle pour détecter les failles de sécurité en Python.
* `file.py` : Fichier à analyser.

**2. Analyse d’un Répertoire**

Pour analyser un projet entier :

```bash
semgrep --config=auto /path/to/project
```

**Explications :**

* `--config=auto` : Identifie automatiquement le langage et utilise des règles pertinentes.

***

**3. Analyse avec une Règle Personnalisée**

Créez une règle dans un fichier YAML, par exemple `rule.yml` :

```yaml
rules:
  - id: no-eval
    pattern: eval(...)
    message: "L'utilisation de eval est dangereuse et doit être évitée."
    languages: [python]
    severity: WARNING
```

Exécutez la règle :

```bash
semgrep --config=rule.yml file.py
```

**Explications :**

* `id` : Identifiant unique de la règle.
* `pattern` : Motif recherché dans le code.
* `message` : Message affiché si le motif est trouvé.
* `languages` : Langage ciblé (Python, JavaScript, etc.).
* `severity` : Niveau de gravité (INFO, WARNING, ERROR).

***

**4. Enregistrement des Résultats**

Pour enregistrer les résultats dans un fichier JSON :

```bash
semgrep --config=python-security file.py --json > results.json
```

***

### **🔍 Étape 3 : Analyse Avancée avec Semgrep**

**1. Utilisation des Règles de la Bibliothèque Officielle**

Semgrep propose une bibliothèque de règles prêtes à l’emploi pour divers objectifs :

1.  **Sécurité Python :**

    ```bash
    semgrep --config=python-security /path/to/project
    ```
2.  **Bonnes pratiques JavaScript :**

    ```bash
    semgrep --config=javascript /path/to/project
    ```
3.  **Recherche de Secrets :**

    ```bash
    semgrep --config=secrets /path/to/project
    ```

Pour voir toutes les configurations disponibles :

```bash
semgrep --config=https://semgrep.dev/p
```

***

**2. Règles Avancées**

Les règles Semgrep peuvent être combinées pour des analyses complexes. Exemple d’une règle avancée détectant des injections SQL en PHP :

```yaml
rules:
  - id: sql-injection
    patterns:
      - pattern: $query = "SELECT * FROM users WHERE id = " . $_GET['id']
      - pattern-not: $query = mysqli_real_escape_string(...)
    message: "Injection SQL possible. Utilisez mysqli_real_escape_string pour échapper les entrées utilisateur."
    languages: [php]
    severity: ERROR
```

***

**3. Ignorer des Fichiers ou Répertoires**

Pour exclure certains chemins :

```bash
semgrep --config=python-security /path/to/project --exclude tests/
```

***

**4. Intégration CI/CD**

Ajoutez Semgrep dans un pipeline CI/CD pour automatiser l’analyse de sécurité :

* Exemple avec GitHub Actions :

```yaml
name: Semgrep
on: [push]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Semgrep
        run: |
          pip install semgrep
          semgrep --config=auto /path/to/project
```

***

### **📋 Étape 4 : Scénarios Pratiques avec Semgrep**

**1. Identifier les Vulnérabilités Connues**

Commande :

```bash
semgrep --config=python-security /path/to/project
```

Cela détecte des problèmes tels que :

* Utilisation de `eval`.
* Mauvaise gestion des exceptions.
* Fichiers ou données sensibles exposés.

**2. Rechercher des Secrets dans le Code**

Commande :

```bash
semgrep --config=secrets /path/to/project
```

Semgrep détecte des données sensibles telles que :

* Clés d’API.
* Mots de passe.
* Informations confidentielles.

**3. Auditer les API Dépréciées**

Créez une règle pour identifier l’utilisation de fonctions ou bibliothèques obsolètes :

```yaml
rules:
  - id: deprecated-api
    pattern: requests.get(...)
    message: "Utilisez httpx à la place de requests.get."
    languages: [python]
    severity: WARNING
```

**4. Validation des Normes de Codage**

Commande :

```bash
semgrep --config=https://semgrep.dev/r/javascript-eslint /path/to/project
```

Cela vérifie si le code suit les standards ESLint.

***

### **🔧 Étape 5 : Optimisation et Personnalisation**

**1. Configuration Locale**

Pour réutiliser plusieurs règles, stockez-les dans un fichier de configuration :

```bash
semgrep --config=local-config.yml /path/to/project
```

**2. Réduction des Faux Positifs**

Affinez vos règles avec :

* `pattern-not` : Exclure certains motifs.
* `metavariables` : Utiliser des variables pour définir des règles précises.

Exemple avec `pattern-not` :

```yaml
rules:
  - id: avoid-os-system
    pattern: os.system(...)
    pattern-not: os.system('echo ...')
    message: "L'utilisation de os.system est risquée."
    languages: [python]
    severity: WARNING
```

***

### **📖 Bonnes Pratiques avec Semgrep**

1. **Intégration CI/CD :** Automatisez l’analyse avec des pipelines pour éviter l’introduction de vulnérabilités dans le code.
2. **Exécution régulière :** Analysez le code après chaque mise à jour ou modification majeure.
3. **Personnalisez vos règles :** Créez des règles spécifiques adaptées à votre projet et langage.
4. **Collaboration :** Partagez vos configurations et règles au sein de votre équipe pour un développement cohérent.
5. **Formez votre équipe :** Familiarisez les développeurs avec Semgrep pour identifier et corriger les problèmes en amont.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
