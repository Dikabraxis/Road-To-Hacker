# Cupp

### **CUPP - Guide Complet**

***

⚠️ **Avertissement :** Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**CUPP** (Common User Passwords Profiler) est un outil open-source permettant de générer des listes de mots de passe personnalisées basées sur des informations spécifiques sur une cible. Il est particulièrement utile pour les pentesters qui veulent optimiser les attaques par dictionnaire.

Avec CUPP, vous pouvez générer une liste de mots de passe pertinente pour une cible en répondant à des questions interactives ou en profilant une liste existante.

***

### **🚀 Étape 1 : Installation de CUPP**

**1.1 Prérequis**

* Python 3 installé sur votre système.
* Git pour cloner le dépôt.

**1.2 Installation sur Linux/MacOS**

1.  Clonez le dépôt officiel de CUPP :

    ```bash
    git clone https://github.com/Mebus/cupp.git
    cd cupp
    ```
2.  Donnez les permissions d'exécution au script principal :

    ```bash
    bashCopier le codechmod +x cupp.py
    ```
3.  Vérifiez que CUPP fonctionne correctement :

    ```bash
    python3 cupp.py -h
    ```

    Une aide avec les options disponibles doit s'afficher.

**1.3 Installation sur Windows**

1. Téléchargez et installez Python depuis [python.org](https://www.python.org/downloads/).
2. Clonez le dépôt avec Git ou téléchargez-le sous forme d'archive ZIP depuis [le dépôt GitHub officiel](https://github.com/Mebus/cupp).
3.  Naviguez dans le répertoire CUPP et exécutez le script avec Python :

    ```bash
    python cupp.py -h
    ```

***

### **🛠️ Étape 2 : Utilisation de CUPP**

**2.1 Génération de Liste de Mots de Passe Personnalisée**

Pour générer une liste personnalisée en répondant à des questions interactives :

```bash
python3 cupp.py -i
```

**Étapes :**

1. Le script vous demandera des informations sur la cible, telles que :
   * Nom, surnom, et prénom.
   * Date de naissance.
   * Noms des proches (conjoint, enfants, etc.).
   * Animaux de compagnie, loisirs, etc.
2.  CUPP génère une liste de mots de passe basée sur ces données. Par exemple :

    ```
    alice1990
    max123
    ali_bob1990
    ```
3. La liste est enregistrée dans un fichier texte dans le répertoire courant.

***

**2.2 Profilage d'une Liste Existante**

Vous pouvez enrichir une liste de mots de passe existante avec l'option `-w` :

```bash
python3 cupp.py -w
```

Cela permet de :

* Analyser une liste de mots de passe existante pour ajouter des variantes spécifiques.
* Générer une liste optimisée.

***

**2.3 Téléchargement de Wordlists**

Pour télécharger des listes de mots de passe massives depuis le dépôt officiel de CUPP :

```bash
python3 cupp.py -l
```

Cela télécharge des fichiers de dictionnaires tels que :

* **rockyou.txt**
* **phpbb.txt**
* Autres wordlists pertinentes.

***

**2.4 Utilisation de la Base de Données Alecto**

CUPP intègre la base de données **Alecto**, qui contient des combinaisons de noms d'utilisateur et de mots de passe par défaut provenant de périphériques réseau courants.

Pour utiliser cette fonctionnalité :

```bash
python3 cupp.py -a
```

CUPP extrait et génère une liste basée sur ces informations pour des tests spécifiques à des équipements comme des routeurs ou des serveurs.

***

**2.5 Vérification de la Version**

Pour afficher la version actuelle de CUPP :

```bash
python3 cupp.py -v
```

***

### **📖 Bonnes Pratiques**

1. **Utiliser CUPP dans un cadre légal :**
   * N'exécutez CUPP que si vous avez une autorisation explicite pour effectuer des tests.
2. **Analyser les listes générées :**
   * Inspectez les listes pour éviter de générer des mots de passe inutiles ou non pertinents.
3. **Sécuriser les listes générées :**
   * Stockez les listes dans des emplacements sécurisés.
   *   Utilisez des outils comme `gpg` pour les chiffrer si nécessaire :

       ```bash
       gpg --encrypt --recipient <email> password_list.txt
       ```
4. **Adapter les attaques aux cibles :**
   * Utilisez CUPP avec d'autres outils comme Hydra ou John the Ripper pour maximiser l'efficacité des tests.

***

#### **Résumé des Options Clés**

| Option | Description                                                                   |
| ------ | ----------------------------------------------------------------------------- |
| `-i`   | Questions interactives pour générer une liste personnalisée.                  |
| `-w`   | Profilage et enrichissement d'une liste de mots de passe existante.           |
| `-l`   | Téléchargement de wordlists massives depuis le dépôt officiel.                |
| `-a`   | Génération de mots de passe par défaut à partir de la base de données Alecto. |
| `-v`   | Affiche la version actuelle du programme.                                     |
| `-h`   | Affiche l'aide et les options disponibles.                                    |

***

### **Conclusion**

**CUPP** est un outil simple mais puissant pour générer des listes de mots de passe adaptées à des cibles spécifiques. En combinant ses fonctionnalités avec des outils comme Hydra, Hashcat ou Medusa, vous pouvez maximiser l'efficacité de vos tests de force brute. Assurez-vous de toujours respecter les règles éthiques et légales dans vos pratiques de cybersécurité.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
