---
layout:
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Curl

### **cURL - Guide Complet et Détaillé**

***

⚠️ **Avertissement :** Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**cURL** (Client URL) est un outil de ligne de commande flexible pour transférer des données à l’aide de divers protocoles tels que HTTP, HTTPS, FTP, SFTP, et bien d’autres. Il est utilisé pour interagir avec des API, tester des points d’entrée, automatiser des transferts de fichiers, et effectuer des tests de sécurité.

Ce guide combine les fonctions essentielles et avancées de cURL pour couvrir à la fois les besoins généraux et spécifiques liés à la cybersécurité et au pentest.

***

### **🚀 Étape 1 : Installation de cURL**

**1.1 Vérifier si cURL est Installé**

Exécutez cette commande pour vérifier si cURL est disponible sur votre système :

```bash
curl --version
```

**Exemple de sortie :**

```makefile
curl 7.x.x (x86_64-pc-linux-gnu) libcurl/7.x.x OpenSSL/1.x.x
Protocols: dict file ftp ftps http https ...
```

***

**1.2 Installer cURL**

Si cURL n'est pas installé, procédez comme suit :

*   **Sur Debian/Ubuntu** :

    ```bash
    sudo apt update
    sudo apt install curl
    ```
*   **Sur CentOS/Red Hat** :

    ```bash
    sudo yum install curl
    ```
* **Sur macOS** : Préinstallé par défaut.
* **Sur Windows** : Téléchargez cURL depuis https://curl.se/download.html.

***

### **🛠️ Étape 2 : Utilisation de Base**

**2.1 Effectuer une Requête GET**

Pour envoyer une requête GET simple :

```bash
curl http://example.com
```

***

**2.2 Effectuer une Requête POST**

Pour envoyer des données via POST :

```bash
curl -X POST -d "param1=value1&param2=value2" http://example.com
```

**Explications :**

* `-X POST` : Spécifie le type de requête (POST).
* `-d` : Envoie des données au serveur.

***

**2.3 Ajouter des En-têtes**

Pour inclure des en-têtes personnalisés dans une requête :

```bash
curl -H "Authorization: Bearer token" http://example.com
```

Pour ajouter plusieurs en-têtes :

```bash
curl -H "Header1: Value1" -H "Header2: Value2" http://example.com
```

***

**2.4 Suivre les Redirections**

Pour suivre automatiquement les redirections HTTP/HTTPS :

```bash
curl -L http://example.com
```

***

### **🔍 Étape 3 : Gestion des Cookies**

**3.1 Envoyer un Cookie**

Pour envoyer un cookie avec une requête :

```bash
curl -b "name=value" http://example.com
```

***

**3.2 Enregistrer et Réutiliser des Cookies**

Enregistrer les cookies dans un fichier :

```bash
curl -c cookies.txt http://example.com
```

Utiliser les cookies enregistrés :

```bash
curl -b cookies.txt http://example.com
```

***

### **📂 Étape 4 : Téléchargement et Gestion de Fichiers**

**4.1 Télécharger un Fichier**

Pour télécharger un fichier depuis un serveur distant :

```bash
curl -O http://example.com/file.txt
```

Pour spécifier un nom de fichier :

```bash
curl -o custom_name.txt http://example.com/file.txt
```

***

**4.2 Téléchargements Multiples**

Télécharger plusieurs fichiers avec une seule commande :

```bash
curl -O http://example.com/file1 -O http://example.com/file2
```

Télécharger une série de fichiers en boucle :

```bash
curl http://example.com/file[1-5].txt
```

***

**4.3 Reprendre un Téléchargement**

Pour reprendre un téléchargement interrompu :

```bash
curl -C - -O http://example.com/file.zip
```

***

#### **🛠️ Étape 5 : Utilisation Avancée dans un Pentest**

**5.1 Tester des Points d'Entrée GET**

Injecter des paramètres dans une URL :

```bash
curl "http://example.com/page?param=FUZZ"
```

***

**5.2 Tester des Points d'Entrée POST**

Injecter des données dans un formulaire ou une API :

```bash
curl -X POST -d "username=FUZZ&password=1234" http://example.com/login
```

***

**5.3 Téléverser un Fichier**

Pour téléverser un fichier via un formulaire HTML :

```bash
curl -X POST -F "file=@/path/to/file.jpg" http://example.com/upload
```

***

**5.4 Mesurer les Temps de Réponse**

Pour analyser les performances du serveur :

```bash
curl -w "Time: %{time_total}s\n" -o /dev/null -s http://example.com
```

***

**5.5 Utiliser un Proxy**

Acheminer le trafic via un proxy :

```bash
curl -x http://127.0.0.1:8080 http://example.com
```

***

**5.6 Authentification Basique**

Pour tester un point d’accès protégé par une authentification :

```bash
curl -u username:password http://example.com/protected
```

***

### **🔍 Étape 6 : Commandes FTP et SFTP**

**6.1 Téléchargement via FTP**

```bash
curl ftp://example.com/file.txt -u username:password
```

***

**6.2 Téléverser un Fichier**

```bash
curl -T localfile ftp://example.com/upload/ -u username:password
```

***

**6.3 Téléchargement via SFTP**

```bash
curl -u username:password sftp://example.com/path/to/file
```

***

### **🛠️ Étape 7 : Debugging et Diagnostics**

**7.1 Activer le Mode Verbeux**

Afficher des détails supplémentaires sur la requête :

```bash
curl -v http://example.com
```

***

**7.2 Tracer la Réponse**

Suivre les étapes de la requête et de la résolution DNS :

```bash
curl --trace trace.txt http://example.com
```

***

**7.3 Exporter une Commande cURL**

Depuis Postman :

1. Effectuez une requête.
2. Cliquez sur **Code** dans le menu.
3. Sélectionnez le format cURL.

***

### **📖 Bonnes Pratiques**

1. **Obtenir des Autorisations**
   * Avant de tester un domaine ou une application, assurez-vous d’avoir une autorisation explicite.
2. **Limiter l’Impact**
   * Utilisez cURL de manière responsable pour éviter de surcharger les serveurs.
3. **Analyser les Résultats**
   *   Combinez cURL avec **jq** pour traiter les réponses JSON :

       ```bash
       curl -s http://example.com/api | jq
       ```
4. **Automatiser avec des Scripts**
   *   Intégrez cURL dans vos scripts pour automatiser les tests :

       ```bash
       for i in {1..100}; do curl "http://example.com/page?param=$i"; done
       ```

***

### **Résumé des Commandes Clés**

| Commande                                | Description                                   |
| --------------------------------------- | --------------------------------------------- |
| `curl http://example.com`               | Effectue une requête GET simple.              |
| `curl -X POST -d "param=value"`         | Effectue une requête POST avec des données.   |
| `curl -H "Authorization: Bearer token"` | Ajoute un en-tête personnalisé.               |
| `curl -O http://example.com/file.txt`   | Télécharge un fichier.                        |
| `curl -x http://127.0.0.1:8080`         | Utilise un proxy pour acheminer les requêtes. |
| `curl -w "Time: %{time_total}"`         | Affiche le temps total de la requête.         |

***

### **Conclusion**

cURL est un outil incroyablement puissant pour interagir avec des serveurs, tester des API, ou analyser des applications web. Grâce à ses multiples options, cURL s’adapte aussi bien aux tâches simples qu’aux scénarios avancés de cybersécurité. Combinez-le avec d’autres outils pour maximiser vos résultats, et utilisez-le toujours de manière éthique et légale.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
