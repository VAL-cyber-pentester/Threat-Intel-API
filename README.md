# 🛡️ API Threat Intelligence

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-green)

API REST avec interface web pour analyser des IPs, hash de fichiers et domaines suspects en utilisant **VirusTotal** et **AbuseIPDB**.

## 🎯 Objectif

Fournir un outil d'analyse de threat intelligence permettant de :
- Vérifier si une IP est malveillante
- Analyser des hash de fichiers suspects
- Vérifier la réputation de domaines
- Enrichir automatiquement des listes d'IOC (Indicators of Compromise)

## ✨ Fonctionnalités

### 🌐 Vérification d'IPs
- Interrogation simultanée de **VirusTotal** et **AbuseIPDB**
- Score de malveillance agrégé
- Informations géographiques et AS
- Recommandations de sécurité

### 🔐 Analyse de Hash
- Support MD5, SHA1, SHA256
- Détections antivirus (VirusTotal)
- Type et taille de fichier
- Noms connus du fichier

### 🌍 Vérification de Domaines
- Réputation du domaine
- Catégorisation
- Détections malveillantes
- Historique d'analyse

### 📊 Enrichissement d'IOC
- Traitement par lot d'IPs, hash et domaines
- Classification automatique du type d'IOC
- Statistiques globales
- Rate limiting intelligent

### 💾 Cache Local
- Base SQLite intégrée
- Expiration configurable (24h par défaut)
- Réduction des appels API
- Performance optimisée

## 🚀 Installation

### Prérequis
- Python 3.8+
- pip

### Installation rapide

```bash
# Cloner le repository
git clone https://github.com/VAL-cyber-pentester/Threat-Intel-API.git
cd Threat-Intel-API

# Installer les dépendances
pip install -r requirements.txt

# Copier le fichier d'environnement
copy .env.example .env

# Lancer l'application
python app.py
```

## 🔑 Configuration des Clés API (Optionnel)

L'application fonctionne sans clés API mais avec des fonctionnalités limitées.

### Obtenir des clés gratuites :

1. **VirusTotal** (4 requêtes/minute)
   - S'inscrire sur : https://www.virustotal.com/gui/join-us
   - Récupérer la clé API dans votre profil

2. **AbuseIPDB** (1000 requêtes/jour)
   - S'inscrire sur : https://www.abuseipdb.com/register
   - Récupérer la clé API dans les paramètres

### Configurer les clés

Éditer le fichier `.env` :

```bash
VIRUSTOTAL_API_KEY=votre_clé_virustotal_ici
ABUSEIPDB_API_KEY=votre_clé_abuseipdb_ici
```

## 📖 Utilisation

### Interface Web

Lancer le serveur :
```bash
python app.py
```

Accéder à l'interface : **http://127.0.0.1:5000**

### API REST

#### 1. Vérifier une IP

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
      "country": "US"
    },
    {
      "source": "AbuseIPDB",
      "abuse_confidence_score": 0,
      "total_reports": 0
    }
  ]
}
```

#### 2. Vérifier un Hash

```bash
curl -X POST http://127.0.0.1:5000/api/check/hash \
  -H "Content-Type: application/json" \
  -d '{"hash": "44d88612fea8a8f36de82e1278abb02f"}'
```

#### 3. Vérifier un Domaine

```bash
curl -X POST http://127.0.0.1:5000/api/check/domain \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

#### 4. Enrichir des IOC

```bash
curl -X POST http://127.0.0.1:5000/api/enrich/ioc \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [
      "8.8.8.8",
      "44d88612fea8a8f36de82e1278abb02f",
      "example.com"
    ]
  }'
```

#### 5. Statut de l'API

```bash
curl http://127.0.0.1:5000/api/status
```

## 📁 Structure du Projet

```
Threat-Intel-API/
├── app.py                 # API Flask principale
├── config.py              # Configuration
├── requirements.txt       # Dépendances Python
├── .env.example           # Template variables d'environnement
├── README.md              # Documentation
├── static/
│   ├── style.css         # Styles CSS
│   └── script.js         # Logique JavaScript
├── templates/
│   └── index.html        # Interface web
└── data/
    └── cache.db          # Cache SQLite (créé automatiquement)
```

## 🛠️ Technologies Utilisées

- **Flask** : Framework web Python
- **Requests** : Requêtes HTTP vers APIs externes
- **SQLite** : Base de données cache
- **VirusTotal API v3** : Analyse de menaces
- **AbuseIPDB API v2** : Base de données d'IPs malveillantes

## ⚙️ Configuration Avancée

### Modifier la durée du cache

Dans `config.py` :
```python
CACHE_EXPIRY_HOURS = 24  # Modifier selon vos besoins
```

### Ajuster le rate limiting

Dans `config.py` :
```python
MAX_REQUESTS_PER_MINUTE = 4  # Pour VirusTotal free
```

## 🎯 Cas d'Usage

- **Analyse SOC** : Vérification rapide d'IPs suspectes
- **Incident Response** : Analyse de hash de malwares
- **Threat Hunting** : Enrichissement d'IOC
- **Pentest** : Validation d'infrastructure cible
- **Formation** : Apprentissage de threat intelligence

## 🔒 Sécurité

- ⚠️ **Ne jamais** commit le fichier `.env` avec vos vraies clés API
- Utiliser HTTPS en production
- Implémenter une authentification pour usage en production
- Rate limiting activé pour éviter l'abus

## 📊 Limitations

### Sans clés API :
- Messages d'erreur indiquant l'absence de clés
- Démonstration de l'interface fonctionnelle

### Avec clés gratuites :
- **VirusTotal** : 4 requêtes/minute, 500/jour
- **AbuseIPDB** : 1000 requêtes/jour
- Fonction d'enrichissement IOC limitée par le rate limiting

## 🚀 Améliorations Futures

- [ ] Support d'APIs supplémentaires (Shodan, AlienVault OTX)
- [ ] Export des résultats (JSON, CSV, PDF)
- [ ] Dashboard de statistiques
- [ ] Authentification utilisateur
- [ ] API key rotation automatique
- [ ] Webhooks pour alertes temps réel
- [ ] Intégration SIEM (Splunk, ELK)

## 📧 Contact

**Valérie ENAME**
- GitHub : [@VAL-cyber-pentester](https://github.com/VAL-cyber-pentester)
- LinkedIn : [Valérie ENAME](https://linkedin.com/in/valérie-ename-02ba7733a)


## 🙏 Remerciements

Projet créé dans le cadre d'un portfolio en cybersécurité pour démontrer :
- Compétences en développement d'API REST
- Intégration d'APIs tierces
- Connaissance de la threat intelligence
- Création d'outils professionnels réutilisables

---

⭐ **Si ce projet vous est utile, n'hésitez pas à lui donner une étoile !**
