# 🛡️ API Threat Intelligence

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?style=for-the-badge&logo=flask)
![APIs](https://img.shields.io/badge/APIs-VirusTotal%20%7C%20AbuseIPDB-orange?style=for-the-badge)

API REST avec interface web pour analyser des IPs, hash de fichiers et domaines suspects en temps réel.

---

## 🎯 Objectif

Créer une plateforme centralisée d'analyse de threat intelligence permettant aux analystes SOC de vérifier rapidement la réputation d'IPs, fichiers et domaines en interrogeant simultanément plusieurs sources de confiance.

---

## ✨ Fonctionnalités

### 🌐 Vérification d'IPs
- **Sources multiples :** VirusTotal + AbuseIPDB
- **Détections :** Malware, botnet, spam, scanning
- **Informations géo :** Pays, AS, ISP
- **Score de confiance :** Agrégation des sources
- **Historique :** Derniers rapports d'abus

### 🔐 Analyse de Hash de Fichiers
- **Support :** MD5, SHA1, SHA256
- **Détections antivirus :** 70+ moteurs (VirusTotal)
- **Métadonnées :** Type de fichier, taille, noms connus
- **Classification :** Malware family identification
- **Score de malveillance :** Consensus des AV

### 🌍 Vérification de Domaines
- **Réputation :** Score global du domaine
- **Catégorisation :** Type de site (malware, phishing, etc.)
- **Détections :** Nombre de moteurs signalant le domaine
- **WHOIS data :** Informations d'enregistrement
- **Historique :** Activité malveillante passée

### 📊 Enrichissement d'IOC
- **Traitement par lot :** Analyse de listes d'IOC
- **Auto-détection :** Classification automatique (IP/hash/domain)
- **Statistiques :** Vue d'ensemble des menaces
- **Export :** Résultats en JSON
- **Rate limiting :** Respect des quotas API

### 💾 Système de Cache
- **Base SQLite :** Stockage local des résultats
- **Expiration configurable :** 24h par défaut
- **Performance :** Réduction du temps de réponse
- **Économie :** Limitation des appels API payants

### 🎨 Interface Web
- **Dashboard moderne :** Design responsive
- **4 onglets intuitifs :** IP, Hash, Domain, IOC
- **Résultats temps réel :** Affichage dynamique
- **Badges de statut :** Malveillant / Légitime
- **Recommandations :** Actions suggérées

---

## 🚀 Installation

### Prérequis
- Python 3.8+
- Clés API (gratuites) :
  - [VirusTotal](https://www.virustotal.com/gui/join-us)
  - [AbuseIPDB](https://www.abuseipdb.com/register)

### Installation

```bash
# Cloner le repository
git clone https://github.com/VAL-cyber-pentester/Threat-Intel-API.git
cd Threat-Intel-API

# Installer les dépendances
pip install -r requirements.txt

# Configurer les clés API
cp .env.example .env
# Éditer .env avec vos clés API
```

---

## 📖 Utilisation

### Démarrer l'API

```bash
python app.py
```

L'API sera accessible sur : **http://127.0.0.1:5000**

### Interface Web

Ouvrir dans un navigateur : http://127.0.0.1:5000

### API REST

#### Vérifier une IP

```bash
curl -X POST http://127.0.0.1:5000/api/check/ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

**Réponse :**
```json
{
  "ip": "8.8.8.8",
  "is_malicious": false,
  "summary": "✅ IP 8.8.8.8 ne semble pas malveillante",
  "recommendation": "Aucune action requise",
  "sources": [
    {
      "source": "VirusTotal",
      "malicious": 0,
      "harmless": 89,
      "country": "US",
      "as_owner": "Google LLC"
    },
    {
      "source": "AbuseIPDB",
      "abuse_confidence_score": 0,
      "total_reports": 0
    }
  ]
}
```

#### Vérifier un Hash

```bash
curl -X POST http://127.0.0.1:5000/api/check/hash \
  -H "Content-Type: application/json" \
  -d '{"hash": "44d88612fea8a8f36de82e1278abb02f"}'
```

#### Vérifier un Domaine

```bash
curl -X POST http://127.0.0.1:5000/api/check/domain \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

#### Enrichir des IOC

```bash
curl -X POST http://127.0.0.1:5000/api/enrich/ioc \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [
      "8.8.8.8",
      "44d88612fea8a8f36de82e1278abb02f",
      "malicious-site.com"
    ]
  }'
```

#### Statut de l'API

```bash
curl http://127.0.0.1:5000/api/status
```

---

## 🛠️ Architecture

```
Threat-Intel-API/
├── app.py                 # API Flask principale
├── config.py              # Configuration
├── requirements.txt       # Dépendances
├── .env                   # Clés API (non versionnée)
├── static/
│   ├── style.css         # Styles interface
│   └── script.js         # Logique front-end
├── templates/
│   └── index.html        # Interface web
└── data/
    └── cache.db          # Cache SQLite
```

---

## 📊 Cas d'Usage Réels

### 🔵 Analyste SOC
```
Scénario : Alerte SIEM pour connexion depuis IP suspecte
Action : Vérification rapide de l'IP via l'API
Résultat : IP identifiée comme botnet, blocage immédiat
Temps gagné : 5 minutes → 30 secondes
```

### 🔴 Incident Response
```
Scénario : Fichier suspect détecté sur poste utilisateur
Action : Analyse du hash MD5 via l'interface
Résultat : Malware connu détecté par 45/70 AV
Décision : Isolation du poste et analyse forensic
```

### 🟡 Threat Hunting
```
Scénario : Liste de 50 IOC d'une campagne APT
Action : Enrichissement batch via API
Résultat : 12 IOC identifiés comme malveillants
Action : Ajout aux règles de blocage firewall
```

---

## 🎓 Ce Que J'ai Appris

### Compétences Techniques
- ✅ Développement d'**API REST** avec Flask
- ✅ Intégration d'**APIs tierces** (VirusTotal, AbuseIPDB)
- ✅ Gestion de **cache** avec SQLite
- ✅ **Rate limiting** et respect des quotas
- ✅ **Parsing JSON** et agrégation de données
- ✅ Développement **front-end** (HTML/CSS/JS)
- ✅ Gestion des **erreurs** et timeout

### Threat Intelligence
- ✅ Comprendre les **IOC** (Indicators of Compromise)
- ✅ Sources de **threat intel** publiques
- ✅ **Enrichissement** de données de sécurité
- ✅ **Scoring** de malveillance
- ✅ Contexte dans l'**incident response**

### Défis Surmontés
- Gestion des limitations API (quotas gratuits)
- Optimisation du cache pour réduire les appels
- Agrégation de scores de sources multiples
- Gestion des timeouts et erreurs réseau
- Interface responsive et intuitive

---

## 🔒 Sécurité des Clés API

⚠️ **IMPORTANT : Protection des clés API**

```bash
# Ne JAMAIS commit le fichier .env
echo ".env" >> .gitignore

# Utiliser des variables d'environnement
export VIRUSTOTAL_API_KEY="votre_clé"
export ABUSEIPDB_API_KEY="votre_clé"
```

---

## ⚙️ Configuration Avancée

### Modifier la durée du cache

Dans `config.py` :
```python
CACHE_EXPIRY_HOURS = 48  # 48h au lieu de 24h
```

### Ajuster le rate limiting

```python
MAX_REQUESTS_PER_MINUTE = 4  # Pour VirusTotal free tier
```

---

## 📈 Limitations

### Sans clés API
- Fonctionnalités limitées
- Messages d'erreur informatifs
- Démo de l'interface uniquement

### Avec clés gratuites
- **VirusTotal** : 4 requêtes/min, 500/jour
- **AbuseIPDB** : 1000 requêtes/jour
- Cache recommandé pour optimisation

---

## 🚀 Améliorations Futures

- [ ] Support de Shodan, AlienVault OTX
- [ ] Export PDF des rapports
- [ ] Dashboard de statistiques
- [ ] Webhooks pour alertes
- [ ] Intégration SIEM (Splunk, ELK)
- [ ] API key rotation automatique
- [ ] Mode multi-tenant
- [ ] Authentification utilisateur

---

## 📚 Ressources

- [VirusTotal API Documentation](https://developers.virustotal.com/reference)
- [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## 📧 Contact

**Valérie ENAME**
- GitHub : [@VAL-cyber-pentester](https://github.com/VAL-cyber-pentester)
- LinkedIn : [Valérie ENAME](https://linkedin.com/in/valérie-ename-02ba7733a)
- Portfolio : [val-cyber-pentester.github.io](https://val-cyber-pentester.github.io/projets)

---

## 📄 License

MIT License - Usage éducatif et professionnel.

---

## 🙏 Remerciements

Projet créé pour démontrer :
- Capacité à développer des APIs REST
- Compréhension de la threat intelligence
- Intégration de services tiers
- Création d'outils utilisables en production

---

⭐ **Si cet outil vous est utile dans votre travail SOC, laissez une étoile !**
