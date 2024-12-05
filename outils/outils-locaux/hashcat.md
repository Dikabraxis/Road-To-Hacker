# Hashcat

## Hashcat - Guide Complet pour le Cracking de Mots de Passe

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### Introduction

**Hashcat** est un outil puissant pour le cracking de mots de passe basé sur des hachages. Il est capable de décrypter des mots de passe à partir de différents algorithmes de hachage, y compris **MD5**, **SHA-1**, **NTLM**, et bien d'autres, en utilisant des attaques par dictionnaire, force brute, ou combinées.

#### Pourquoi utiliser Hashcat ?

* **Rapidité** : Utilise les GPU pour des performances optimales.
* **Flexibilité** : Supporte divers modes d'attaque et types de hachages.
* **Personnalisable** : Permet l'utilisation de règles, masques et combinaisons.

***

### 🚀 Étape 1 : Installation de Hashcat

***

#### Installation sur Linux

1. **Télécharger Hashcat** :
   * Depuis le site officiel : https://hashcat.net/hashcat/.
2.  **Décompresser l’archive** :

    ```bash
    tar -xvf hashcat-X.X.X.7z
    ```
3. **Configurer Hashcat** :
   *   Déplacez l'exécutable vers un répertoire accessible globalement :

       ```bash
       sudo mv hashcat /usr/local/bin/
       ```
4.  **Tester l’installation** :

    ```bash
    hashcat --version
    ```

***

#### Installation sur Windows

1. **Télécharger l'archive** :
   * Rendez-vous sur https://hashcat.net/hashcat/ et téléchargez la dernière version pour Windows.
2. **Extraire l’archive ZIP** :
   * Décompressez dans un répertoire comme `C:\Hashcat`.
3. **Ajouter le chemin au PATH système** :
   * Accédez à **Paramètres > Système > Paramètres système avancés > Variables d’environnement** et ajoutez le chemin de `hashcat.exe` à la variable `PATH`.
4. **Tester l’installation** :
   *   Ouvrez une invite de commande et exécutez :

       ```bash
       hashcat --version
       ```

***

#### Installation sur macOS

1. **Télécharger Hashcat** :
   * Depuis https://hashcat.net/hashcat/.
2.  **Installer les dépendances nécessaires** :

    ```bash
    brew install gcc
    ```
3.  **Décompresser l’archive** et ajouter Hashcat au PATH :

    ```bash
    mv hashcat /usr/local/bin/
    ```
4.  **Vérifier l’installation** :

    ```bash
    hashcat --version
    ```

***

### 🛠️ Étape 2 : Utilisation de Base de Hashcat

***

#### 1. Cracker un Hachage avec un Dictionnaire

*   **Commande** :

    ```bash
    hashcat -m 0 -a 0 hashes.txt wordlist.txt
    ```
* **Explication** :
  * `-m 0` : Spécifie le type de hachage (**0** pour MD5).
  * `-a 0` : Définit le mode d’attaque (**0** pour dictionnaire).
  * `hashes.txt` : Contient les hachages à décrypter.
  * `wordlist.txt` : Liste de mots à tester.

> 💡 **Astuce** : Utilisez des wordlists populaires comme celles de [SecLists](https://github.com/danielmiessler/SecLists).

***

#### 2. Attaque par Force Brute

*   **Commande** :

    ```bash
    hashcat -m 0 -a 3 hashes.txt ?a?a?a?a
    ```
* **Explication** :
  * `-a 3` : Mode force brute.
  * `?a?a?a?a` : Définit un masque avec 4 caractères, où :
    * `?a` inclut toutes les lettres, chiffres et symboles.

> 💡 **Astuce** : Ajustez le masque pour des longueurs plus grandes ou des types spécifiques (voir section masques ci-dessous).

***

#### 3. Attaque Combinée

*   **Commande** :

    ```bash
    hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt
    ```
* **Explication** :
  * `-a 1` : Combine les mots de deux listes pour former des combinaisons.

***

#### 4. Optimisation avec le GPU

*   Par défaut, Hashcat utilise le GPU pour accélérer le processus. Si ce n'est pas le cas, vous pouvez forcer son utilisation avec :

    ```bash
    hashcat --force -D 1,2
    ```

    * `1` : Force l’utilisation du CPU.
    * `2` : Force l’utilisation du GPU.

***

### 🔍 Étape 3 : Options Avancées

***

#### 1. Attaques avec Masques

Les masques permettent de spécifier des schémas pour les mots de passe :

*   **Commande de base** :

    ```bash
    hashcat -m 0 -a 3 hashes.txt ?u?l?l?d
    ```

    * `?u` : Une lettre majuscule.
    * `?l` : Une lettre minuscule.
    * `?d` : Un chiffre.

**Exemple : Forcer un mot de passe alphanumérique de 6 caractères**

```bash
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?d?d
```

***

#### 2. Attaque par Règles

Les règles modifient dynamiquement les mots du dictionnaire pour générer de nouvelles variations (exemple : ajout de chiffres ou de symboles).

*   **Commande** :

    ```bash
    hashcat -m 0 -a 0 -r rules.txt hashes.txt wordlist.txt
    ```
* **Explication** :
  * `-r rules.txt` : Applique les règles définies dans le fichier `rules.txt`.

> 💡 **Astuce** : Utilisez les règles intégrées comme `rockyou-30000.rule` pour des attaques efficaces.

***

#### 3. Cracker des Hachages Complexes

Consultez la liste complète des types de hachages pris en charge avec :

```bash
hashcat --help
```

Exemples :

*   **MD5** :

    ```bash
    hashcat -m 0 -a 0 hashes.txt wordlist.txt
    ```
*   **SHA-1** :

    ```bash
    hashcat -m 100 -a 0 hashes.txt wordlist.txt
    ```
*   **NTLM** :

    ```bash
    hashcat -m 1000 -a 0 hashes.txt wordlist.txt
    ```

***

### 📋 Étape 4 : Scénarios Pratiques

***

#### 1. Casser des Hachages avec un Dictionnaire

*   **Commande** :

    ```bash
    hashcat -m 0 -a 0 hashes.txt wordlist.txt
    ```
* **Explication** :
  * Teste tous les mots de la liste `wordlist.txt` contre les hachages MD5.

***

#### 2. Attaque par Force Brute avec Symboles

*   **Commande** :

    ```bash
    hashcat -m 0 -a 3 hashes.txt ?u?l?l?s?s
    ```
* **Explication** :
  * Force brute un mot de passe composé d’une majuscule, deux minuscules, et deux symboles.

***

#### 3. Optimisation GPU pour des Hachages NTLM

*   **Commande** :

    ```bash
    hashcat -m 1000 -a 0 hashes.txt wordlist.txt --gpu-temp-abort=85
    ```
* **Explication** :
  * Limite la température maximale du GPU à 85°C pour éviter la surchauffe.

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations légales** :
   * Cracker des hachages sans autorisation est illégal. Utilisez Hashcat uniquement dans des environnements autorisés.
2. **Utilisez des wordlists pertinentes** :
   * Les listes comme `rockyou.txt` ou celles disponibles sur [SecLists](https://github.com/danielmiessler/SecLists) sont idéales.
3. **Surveillez les performances** :
   * Utilisez les options `--status` pour surveiller le progrès en temps réel.
4. **Sauvegardez les sessions** :
   * Si le cracking est interrompu, vous pouvez reprendre avec `--session` et `--restore`.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
