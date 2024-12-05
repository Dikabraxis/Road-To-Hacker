# Sublist3r

## Sublist3r - Guide Complet pour la Découverte de Sous-Domaines

***

### Introduction

**Sublist3r** est un outil de reconnaissance puissant conçu pour identifier les sous-domaines d’un domaine cible. Il collecte des informations en interrogeant des moteurs de recherche, des services d'API, et d'autres sources publiques. Cet outil est essentiel pour les pentesters et les analystes de sécurité souhaitant élargir leur surface d'attaque ou mieux comprendre l'architecture d'un domaine.

***

### 🚀 Étape 1 : Installation de Sublist3r

***

#### 1. Cloner le Dépôt GitHub

Exécutez les commandes suivantes pour télécharger et configurer Sublist3r :

```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
```

* **Explications** :
  * `git clone` : Télécharge le dépôt GitHub contenant les fichiers du projet.
  * `cd Sublist3r` : Navigue dans le répertoire cloné.

***

#### 2. Installer les Dépendances

Installez les modules nécessaires en exécutant :

```bash
pip install -r requirements.txt
```

* **Explication** :
  * `-r requirements.txt` : Installe automatiquement toutes les bibliothèques Python nécessaires à partir du fichier `requirements.txt`.

***

#### 3. Tester l’Installation

Lancez la commande suivante pour vérifier que Sublist3r est installé correctement :

```bash
python sublist3r.py -h
```

* **Résultat attendu** : Une liste d'options disponibles pour utiliser Sublist3r.

***

### 🛠️ Étape 2 : Commandes de Base

***

#### 1. Scanner un Domaine pour Trouver des Sous-Domaines

```bash
python sublist3r.py -d example.com
```

* **Explication** :
  * `-d` : Spécifie le domaine cible à analyser.
*   **Exemple de Résultat** :

    ```csharp
    [INFO] Enumerating subdomains now for example.com
    [INFO] Found subdomain: www.example.com
    [INFO] Found subdomain: mail.example.com
    [INFO] Found subdomain: api.example.com
    ```

***

#### 2. Exporter les Résultats dans un Fichier

Pour sauvegarder les sous-domaines trouvés dans un fichier texte :

```bash
python sublist3r.py -d example.com -o subdomains.txt
```

* **Explication** :
  * `-o` : Enregistre les sous-domaines trouvés dans le fichier `subdomains.txt`.

***

#### 3. Utiliser des Moteurs de Recherche pour les Sous-Domaines

Sublist3r peut interroger des moteurs de recherche spécifiques pour élargir la portée de sa recherche :

```bash
python sublist3r.py -d example.com -b
```

* **Explication** :
  * `-b` : Active la recherche sur des moteurs tels que Google, Bing, Yahoo, Baidu, et Ask.

***

### 🔍 Étape 3 : Commandes Avancées

***

#### 1. Utiliser des Services d’API pour la Recherche

Sublist3r peut interagir avec des services d'API comme VirusTotal pour des recherches plus approfondies :

```bash
python sublist3r.py -d example.com -a
```

* **Explication** :
  * `-a` : Active l’utilisation des services d’API pour améliorer les résultats.

***

#### 2. Scanner Plusieurs Domaines

Vous pouvez effectuer un scan sur plusieurs domaines en une seule commande en ajoutant un script pour parcourir une liste de domaines :

```bash
for domain in $(cat domains.txt); do python sublist3r.py -d $domain -o $domain.txt; done
```

* **Explication** :
  * `domains.txt` : Contient une liste de domaines à analyser.
  * Chaque domaine est scanné et les résultats sont sauvegardés dans un fichier correspondant (par exemple, `example.com.txt`).

***

#### 3. Augmenter la Vitesse de Scan

Pour accélérer le processus, vous pouvez augmenter le nombre de threads utilisés par Sublist3r :

```bash
python sublist3r.py -d example.com -t 50
```

* **Explication** :
  * `-t` : Spécifie le nombre de threads (par défaut : 10). Une valeur plus élevée accélère le scan mais peut augmenter la charge sur le réseau cible.

***

#### 4. Combiner avec un Proxy

Pour masquer votre origine ou passer par un proxy :

```bash
python sublist3r.py -d example.com --proxy http://127.0.0.1:8080
```

* **Explication** :
  * `--proxy` : Acheminer les requêtes via un proxy HTTP.

***

### 📋 Étape 4 : Exemples de Scénarios

***

#### Exemple 1 : Recherche de Sous-Domaines avec Exportation

Pour analyser un domaine et sauvegarder les résultats dans un fichier texte :

```bash
python sublist3r.py -d example.com -o example_subdomains.txt
```

* **Résultat attendu** : Un fichier `example_subdomains.txt` contenant tous les sous-domaines identifiés.

***

#### Exemple 2 : Recherche Basée sur des Moteurs de Recherche

Pour maximiser la couverture en activant les moteurs de recherche intégrés :

```bash
python sublist3r.py -d example.com -b -o subdomains_with_search.txt
```

* **Résultat attendu** : Liste des sous-domaines collectés à l'aide des moteurs de recherche, exportés dans `subdomains_with_search.txt`.

***

#### Exemple 3 : Recherche Avancée avec Services d’API

Pour utiliser des services comme VirusTotal :

```bash
python sublist3r.py -d example.com -a -o api_results.txt
```

* **Résultat attendu** : Sous-domaines identifiés grâce aux services d’API, exportés dans `api_results.txt`.

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations

* **Important** : Ne testez jamais un domaine sans autorisation explicite.
* **Légal** : Assurez-vous que vos actions respectent les lois et politiques en vigueur.

#### 2. Limiter l'Impact

* Réduisez la charge sur les serveurs en limitant le nombre de threads.
* Utilisez un proxy pour éviter d'être détecté comme une source d'activité suspecte.

#### 3. Combiner avec d’Autres Outils

Pour une reconnaissance plus approfondie, combinez Sublist3r avec des outils comme **Nmap** ou **Amass** pour scanner les sous-domaines trouvés et identifier des vulnérabilités potentielles.

***

### Conclusion

**Sublist3r** est un outil indispensable pour la collecte de sous-domaines dans les phases de reconnaissance. Grâce à sa simplicité et à ses fonctionnalités avancées, il s’intègre parfaitement dans le workflow des pentesters et des analystes en cybersécurité.
