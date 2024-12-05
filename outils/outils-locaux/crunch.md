# Crunch

### **Crunch - Guide Complet pour Générer des Listes de Mots de Passe**

***

### **Introduction**

**Crunch** est un outil de génération de listes de mots de passe. Il est conçu pour créer des combinaisons possibles de mots de passe en fonction des critères définis par l'utilisateur, comme la longueur, les caractères autorisés, et les motifs spécifiques. Cet outil est souvent utilisé dans les tests d'intrusion pour alimenter les outils de force brute tels que **Hydra** ou **John the Ripper**.

**Principales fonctionnalités :**

* Génération de listes de mots de passe basées sur des motifs.
* Support des caractères personnalisés.
* Génération optimisée pour éviter de remplir les disques grâce à l’utilisation directe en pipeline.

***

### **🚀 Étape 1 : Installation de Crunch**

**1. Installation sur Linux (Debian/Ubuntu)**

1.  Mettez à jour vos paquets :

    ```bash
    sudo apt update
    ```
2.  Installez Crunch :

    ```bash
    sudo apt install crunch
    ```
3.  Vérifiez l’installation :

    ```bash
    crunch --version
    ```

***

**2. Installation sur macOS**

1.  Installez **Homebrew** (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2.  Installez Crunch :

    ```bash
    brew install crunch
    ```
3.  Vérifiez l’installation :

    ```bash
    crunch --version
    ```

***

**3. Installation sur Windows**

Crunch n’est pas nativement disponible pour Windows, mais vous pouvez :

1. Installer une distribution Linux via **WSL** ou une machine virtuelle.
2. Suivre les étapes pour Linux.

***

### **🛠️ Étape 2 : Utilisation de Base de Crunch**

**1. Générer une Liste de Mots de Passe Simple**

Commande :

```bash
crunch 4 4
```

**Explications :**

* `4 4` : Génère des mots de passe de longueur exacte 4 caractères.
* Par défaut, Crunch utilise l'alphabet complet (`abcdefghijklmnopqrstuvwxyz`).

**Exemple de sortie :**

```python-repl
aaaa
aaab
aaac
...
zzzy
zzzz
```

***

**2. Spécifier des Caractères Personnalisés**

Commande :

```bash
crunch 4 4 abc123
```

**Explications :**

* Utilise uniquement les caractères `a`, `b`, `c`, `1`, `2`, et `3`.

**Exemple de sortie :**

```python-repl
aaaa
aaab
aaac
...
3333
```

***

**3. Générer des Listes Basées sur des Motifs**

Commande :

```bash
crunch 6 6 -t @@##@@
```

**Explications :**

* `-t` : Définit un motif.
* `@` : Représente une lettre minuscule.
* `#` : Représente un chiffre.

**Exemple de sortie :**

```python-repl
aa00aa
aa00ab
aa00ac
...
zz99zz
```

***

**4. Sauvegarder les Résultats dans un Fichier**

Commande :

```bash
crunch 4 4 abc123 -o passwords.txt
```

**Explications :**

* `-o` : Spécifie le fichier de sortie (`passwords.txt`).

***

**5. Rediriger la Sortie vers un Outil**

Au lieu de sauvegarder les mots de passe dans un fichier, vous pouvez les envoyer directement à un outil comme **Hydra** :

```bash
crunch 6 6 abc123 | hydra -l username -P - <target>
```

**Explications :**

* La sortie de Crunch (`-`) est directement utilisée comme entrée pour **Hydra**.

***

### **🔍 Étape 3 : Options Avancées**

**1. Limiter les Combinaisons Générées**

Pour générer uniquement des combinaisons commençant par `ab` :

```bash
crunch 6 6 abc123 -s ab
```

**Explications :**

* `-s ab` : Commence à partir de `ab`.

***

**2. Spécifier une Taille Maximale du Fichier**

Pour générer un fichier de 10 Mo maximum :

```bash
crunch 6 6 abc123 -o START -b 10mb
```

**Explications :**

* `-b 10mb` : Divise les résultats en fichiers de 10 Mo.
* Les fichiers sont nommés automatiquement (`START1.txt`, `START2.txt`, etc.).

***

**3. Ajouter des Caractères Supplémentaires**

Ajoutez des majuscules et des symboles :

```bash
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha-numeric-all
```

**Explications :**

* `-f` : Utilise un fichier de caractères prédéfini.
* `mixalpha-numeric-all` : Inclut des lettres (majuscules/minuscules), chiffres, et symboles.

***

**4. Générer Basé sur des Préfixes**

Ajoutez un préfixe fixe à toutes les combinaisons :

```bash
crunch 6 6 abc123 -p 123
```

**Explications :**

* `-p 123` : Préfixe toutes les combinaisons avec `123`.

**Exemple de sortie :**

```python-repl
123aaa
123aab
123aac
...
123333
```

***

### **📋 Étape 4 : Exemples de Scénarios Pratiques**

**1. Générer une Liste pour un Mot de Passe Numérique**

Si le mot de passe cible est un PIN de 4 chiffres :

```bash
crunch 4 4 0123456789
```

* Utilise uniquement les chiffres 0-9.

***

**2. Générer des Mots de Passe Basés sur des Modèles**

Pour tester des mots de passe au format "ab12CD" :

```bash
crunch 6 6 -t @@##@@
```

***

**3. Générer une Liste pour des Tests Personnalisés**

Pour tester des mots de passe incluant des noms et des chiffres :

```bash
crunch 8 8 -t Adam####
```

**Explications :**

* Génère des mots comme `Adam0001`, `Adam1234`, etc.

***

**4. Générer et Envoyer en Pipeline**

Pour éviter de générer des fichiers volumineux, utilisez un pipeline :

```bash
crunch 6 6 abc123 | john --wordlist=-
```

**Explications :**

* Les mots de passe sont directement utilisés par **John the Ripper**.

***

### **📖 Bonnes Pratiques avec Crunch**

1. **Soyez Efficace :** Définissez des motifs ou des caractères spécifiques pour limiter les combinaisons inutiles.
2. **Redirigez les Résultats :** Utilisez les pipelines pour éviter de saturer le disque.
3. **Testez avec Autorisation :** Assurez-vous d'avoir la permission avant d'utiliser Crunch dans un test d'intrusion.
4. **Optimisez les Listes :** Combinez Crunch avec des dictionnaires existants pour maximiser vos chances.

***

Crunch est un outil puissant pour générer des listes de mots de passe personnalisées. Son flexibilité, combinée à des outils de pentest comme Hydra ou John the Ripper, en fait un atout essentiel pour les tests de sécurité.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
