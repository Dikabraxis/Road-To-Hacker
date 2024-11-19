# Hashcat

#### Introduction

Hashcat est un outil de craquage de mots de passe hautement performant qui peut déchiffrer des hachages en utilisant des méthodes diverses et puissantes. Il prend en charge une large gamme de types de hachage et utilise le matériel GPU pour accélérer les attaques.

#### Installation de Hashcat

**Installation sur Linux**

1.  **Installer via apt (pour les distributions basées sur Debian)** :

    ```bash
    sudo apt update
    sudo apt install hashcat
    ```

    * **Explication** : Met à jour la liste des paquets et installe Hashcat.
2. **Installation depuis les sources** :
   * **Télécharger** : Depuis le site officiel de Hashcat.
   *   **Décompresser et installer** :

       ```bash
       tar -xf hashcat-*.tar.gz
       cd hashcat-*
       sudo make install
       ```
   * **Explication** : Télécharge, décompresse et installe Hashcat depuis les sources.

**Installation sur Windows**

1. **Télécharger Hashcat** depuis le site officiel.
2. **Décompresser l'archive** et placer l'exécutable dans un répertoire accessible.
   * **Explication** : Télécharge et décompresse Hashcat pour une utilisation sur Windows.

#### Utilisation de Base

**1. Décrypter un Hachage avec un Dictionnaire**

*   **Commande de base pour une attaque par dictionnaire** :

    ```bash
    hashcat -m 0 -a 0 hashes.txt wordlist.txt
    ```

    * **Explication** :
      * `-m 0` : Spécifie le type de hachage (0 pour MD5). Consulte la liste des modes pour d'autres types de hachages.
      * `-a 0` : Spécifie le mode d'attaque (0 pour attaque par dictionnaire).
      * `hashes.txt` : Fichier contenant les hachages à casser.
      * `wordlist.txt` : Fichier de dictionnaire contenant les mots de passe à tester.

**2. Attaque par Force Brute**

*   **Lancer une attaque par force brute** :

    ```bash
    hashcat -m 0 -a 3 hashes.txt ?a?a?a?a
    ```

    * **Explication** :
      * `-a 3` : Spécifie le mode d'attaque (3 pour force brute).
      * `?a?a?a?a` : Décrit le masque de l'attaque (4 caractères, tous les types de caractères possibles).


*   **Exemple avec des longueurs variables** :

    ```bash
    hashcat -m 0 -a 3 hashes.txt ?a?l?d?s
    ```

    * **Explication** :
      * `?a` : Tout caractère (lettres, chiffres, symboles).
      * `?l` : Lettres minuscules.
      * `?d` : Chiffres.
      * `?s` : Symboles.

3. **Attaque Combinée**

*   **Combiner deux listes de mots pour former des mots de passe** :

    ```bash
    hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt
    ```

    * **Explication** :
      * `-a 1` : Spécifie le mode d'attaque combinée.
      * `wordlist1.txt` et `wordlist2.txt` : Deux fichiers de dictionnaires à combiner.



**4. Utilisation de GPU**

* **Optimiser l'utilisation du GPU** :
  * Hashcat utilise automatiquement le GPU si disponible. Aucune option spéciale n’est requise pour l'utiliser.

#### Options Avancées

**1. Attaque par Règles**

*   **Appliquer des règles pour modifier les mots de passe** :

    ```bash
    hashcat -m 0 -a 0 -r rules.txt hashes.txt wordlist.txt
    ```

    * **Explication** :
      * `-r rules.txt` : Applique des règles définies dans le fichier `rules.txt` pour transformer les mots de passe du dictionnaire.



**2. Utiliser un Mode de Hachage Spécifique**

*   **Consulter la liste des modes de hachage disponibles** :

    ```bash
    hashcat -h
    ```

    * **Explication** : Affiche l'aide et la liste des modes de hachage disponibles dans Hashcat.



#### Exemples d'Attaques

**1. Cracking des Hachages MD5**

*   **Commande pour MD5** :

    ```bash
    hashcat -m 0 -a 0 hashes.txt wordlist.txt
    ```



**2. Cracking des Hachages SHA-1**

*   **Commande pour SHA-1** :

    ```bash
    hashcat -m 100 -a 0 hashes.txt wordlist.txt
    ```



**3. Cracking des Hachages NTLM**

*   **Commande pour NTLM** :

    ```bash
    hashcat -m 1000 -a 0 hashes.txt wordlist.txt
    ```

