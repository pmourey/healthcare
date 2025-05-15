# 🩺 Healthcare – Historique médical simplifié pour les médecins non informatisés

**Healthcare** est une application web légère et sécurisée, conçue pour aider les médecins à conserver un historique structuré des **consultations et données patient**.

💡 Développée avec [Flask](https://flask.palletsprojects.com/), hébergée sur [PythonAnywhere](https://www.pythonanywhere.com/), cette solution vise particulièrement les professionnels de santé **non équipés de logiciels métiers**.

---

## ✨ Fonctionnalités principales

- 🔐 Authentification par e-mail
- 👤 Gestion de fiches patient
- 📝 Saisie des consultations :
  - Motif, diagnostic, traitement, remarques
- 📊 **Visualisation graphique de données cliniques dans le temps** :
  - Poids
  - Tension artérielle
  - Température
  - Glycémie (ou autre indicateur personnalisé)
- 📂 Historique patient consultable à tout moment
- 🧭 Interface simple et intuitive, utilisable depuis un navigateur

## 📈 Visualisation des données de santé

Chaque patient peut avoir des mesures de santé suivies dans le temps (ex. poids, tension, etc.).  
Celles-ci sont affichées sous forme de **graphiques interactifs** pour permettre au médecin d’évaluer l'évolution de l’état de santé du patient.

Exemples :
- 📉 Évolution du poids
- 🩺 Suivi de la tension systolique / diastolique
- 🌡️ Courbe de température

Les graphiques sont générés automatiquement à partir des consultations enregistrées.

> Affichage basé sur [Chart.js](https://www.chartjs.org/)

---

## 👨‍⚕️ Pour qui ?

- Médecins généralistes en exercice libéral
- Médecins remplaçants
- Médecins en zone rurale ou à faible équipement informatique
- Praticiens en mission humanitaire

---

## 🌐 Démonstration

👉 Accès à la démo (version de test, données non conservées) :  
[https://healthcare06.pythonanywhere.com](https://healthcare06.pythonanywhere.com)  

---

## ⚙️ Installation locale (pour usage personnel ou test)

### Pré-requis :
- Python 3.8+
- pip

### Étapes :

```bash
git clone https://github.com/pmourey/healthcare.git
cd healthcare
python -m venv venv
source venv/bin/activate  # sous Windows : venv\Scripts\activate
pip install -r requirements.txt
flask run
```

L’application est alors accessible à l’adresse : http://127.0.0.1:5000

---

## 🔐 Authentification & sécurité

* Connexion par email (mot de passe sécurisé)
* Possibilité de déploiement sur un serveur personnel
* Aucune collecte de données externes
* Respect du secret médical : l’hébergement est **sous contrôle de l’utilisateur**

---

## 🗃️ Données & sauvegarde

* Stockage SQLite local ou sur l’espace PythonAnywhere
* Export CSV ou PDF des données (à venir)

---

## 🧱 Tech stack

* Python + Flask
* HTML / CSS
* SQLite (ou autre base selon configuration)
* Hébergement : PythonAnywhere (grille gratuite ou payante)

---

## 🎯 Objectifs du projet

> Fournir un outil minimaliste, accessible et sans abonnement pour permettre aux professionnels de santé de :
>
> * Démarrer une démarche de structuration des soins
> * Garder une trace utile des consultations
> * Transitionner en douceur vers un usage numérique

---

## 💬 Contact & contributions

Vous êtes médecin et intéressé ? Avez des suggestions ?
👉 Contactez-moi ici via GitHub ou ouvrez une issue !

Les contributions sont bienvenues.

---

## 📄 Licence

Ce projet est sous licence MIT.

---

## 🔎 Mots-clés

`médecine` `consultation` `dossier patient` `flask` `outil santé` `pythonanywhere` `non informatisé` `libéral` `généraliste`


