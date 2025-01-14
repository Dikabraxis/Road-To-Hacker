# Cupp

### **CUPP - Guide Complet**

***

⚠️ **Avertissement :** Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**CUPP** (Common User Passwords Profiler) est un outil open-source permettant de générer des listes de mots de passe personnalisées basées sur des informations spécifiques sur une personne cible. Il est couramment utilisé dans les tests d'intrusion pour simuler des attaques par force brute ou par dictionnaire.

L'objectif principal de CUPP est de rendre les listes de mots de passe plus pertinentes en utilisant des données personnelles qui pourraient être utilisées par la cible pour créer son mot de passe.

***

### **🚀 Étape 1 : Installation de CUPP**

**1.1 Prérequis**

* Python 3 installé sur votre système.
* Git pour cloner le dépôt.

**1.2 Installation sur Linux/MacOS**

1.  Clonez le dépôt CUPP officiel :

    ```bash
    git clone https://github.com/Mebus/cupp.git
    cd cupp
    ```
2.  Donnez les permissions d'exécution au script principal :

    ```bash
    chmod +x cupp.py
    ```
3.  Vérifiez que CUPP fonctionne correctement :

    ```bash
    python3 cupp.py -h
    ```

    Une liste des options disponibles devrait s'afficher.

**1.3 Installation sur Windows**

1. Téléchargez et installez Python depuis [python.org](https://www.python.org/downloads/).
2. Clonez le dépôt avec Git ou téléchargez-le sous forme d'archive ZIP depuis [le dépôt GitHub](https://github.com/Mebus/cupp).
3.  Naviguez dans le répertoire CUPP et exécutez le script avec Python :

    ```bash
    python cupp.py -h
    ```

***

### **🛠️ Étape 2 : Utilisation de Base de CUPP**

**2.1 Génération de Listes de Mots de Passe Personnalisées**

1.  Lancez CUPP avec la commande interactive :

    ```bash
    python3 cupp.py -i
    ```
2.  Répondez aux questions posées sur la cible (nom, date de naissance, surnom, etc.). Ces informations seront utilisées pour générer une liste de mots de passe.

    **Exemple :**

    * Nom : Alice
    * Surnom : Ali
    * Date de naissance : 1990
    * Nom du conjoint : Bob
    * Loisirs : peinture
    * Enfants : Non
    * Animaux : Oui (nom : Max)
3.  La liste de mots de passe est générée dans un fichier `.txt`, prêt à être utilisé.

    **Exemple de mots de passe générés :**

    ```python-repl
    alice1990
    ali123
    max1990
    bobali
    ...
    ```

**2.2 Utilisation de Listes de Mots de Passe Publiques**

Pour télécharger et utiliser des listes de mots de passe publiques intégrées dans CUPP, utilisez l’option `-w` :

```bash
python3 cupp.py -w
```

Cela télécharge des listes populaires comme **rockyou.txt**, **crunch.txt**, et d'autres.

***

### **🔍 Étape 3 : Utilisation Avancée**

**3.1 Ajouter des Informations Supplémentaires**

Pour enrichir les mots de passe générés, vous pouvez ajouter vos propres informations dans un fichier `.txt` et demander à CUPP d'intégrer ces données :

```bash
python3 cupp.py -i --file additional_info.txt
```

***

**3.2 Mélanger plusieurs Fichiers**

Pour combiner plusieurs listes de mots de passe dans un seul fichier :

```bash
cat file1.txt file2.txt > combined.txt
```

***

**3.3 Générer des Combinaisons**

CUPP peut générer des variations en combinant plusieurs champs pour maximiser les probabilités :

```bash
python3 cupp.py -c
```

***

### **📖 Bonnes Pratiques**

1. **Limiter l’utilisation à un cadre éthique :**\n Utilisez CUPP uniquement dans des environnements où vous avez reçu une autorisation explicite pour tester la sécurité.
2. **Analyser la pertinence des listes :**\n Ne surchargez pas les attaques de force brute avec des listes inutiles. Les listes générées doivent être adaptées à la cible.
3. **Sécuriser les données sensibles :**\n Chiffrez les fichiers de mots de passe générés pour éviter toute fuite accidentelle.

***

#### **Résumé des Commandes Clés**

| Commande                           | Description                                      |
| ---------------------------------- | ------------------------------------------------ |
| `python3 cupp.py -i`               | Générer une liste personnalisée interactivement. |
| `python3 cupp.py -w`               | Télécharger et utiliser des listes publiques.    |
| `python3 cupp.py -i --file <file>` | Ajouter des données supplémentaires.             |
| `python3 cupp.py -c`               | Générer des combinaisons complexes.              |

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
