# GTFOBins

### **Tuto GTFObins**

### **Introduction**

GTFObins est une ressource en ligne essentielle pour les pentesters et les chercheurs en sécurité. Il regroupe des exemples concrets d'abus d'exécutables Unix/Linux afin d'exécuter des commandes arbitraires, d'obtenir un shell, ou d'extraire des informations.

**Accéder à GTFObins**

* URL : [GTFObins](https://gtfobins.github.io/)

### **Fonctionnalités principales :**

* **Recherche d'exécutables abusables :** Parcourir ou rechercher des commandes Unix/Linux spécifiques pouvant être exploitées.
* **Exemples pratiques :** Chaque exécutable est accompagné de scénarios d'abus, comme l'escalade de privilèges, l'exfiltration, ou les manipulations de fichiers.
* **Filtrage par capacité :** Rechercher les exécutables en fonction de capacités spécifiques comme `SUID`, `sudo`, ou `shell`.

### **Comment utiliser GTFObins**

1. **Rechercher un exécutable :**
   * Accédez à [GTFObins](https://gtfobins.github.io/) et utilisez la barre de recherche pour trouver un exécutable (ex. : `vim`).
2. **Examiner les scénarios d'abus :**
   * Cliquez sur l'exécutable pour accéder aux différentes techniques possibles :
     * **SUID abuse** : Si le binaire possède le bit SUID, suivez les instructions pour exploiter cette propriété.
     * **sudo abuse** : Si le binaire peut être exécuté avec sudo, utilisez les commandes fournies pour exploiter les privilèges root.
     * **Shell** : Méthodes pour obtenir un shell interactif à partir de l'exécutable.
3. **Appliquer le scénario :**
   * Copiez les commandes proposées pour les tester dans un environnement sécurisé.
   *   Exemple pour `vim` avec sudo :

       ```bash
       sudo vim -c ':!/bin/bash'
       ```

***

### **Bonnes Pratiques pour les Deux Ressources :**

* **Utilisation Éthique :** Ces outils sont conçus pour l'apprentissage et les tests de sécurité éthiques uniquement.
* **Test en Environnement Sécurisé :** Utilisez des machines virtuelles ou des environnements isolés pour tester les scénarios.
* **Mises à Jour Régulières :** Consultez fréquemment ces référentiels, car de nouveaux outils et méthodes y sont régulièrement ajoutés.
