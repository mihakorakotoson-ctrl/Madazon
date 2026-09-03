# Madazon V9

## Lancement local

Prérequis : Node.js 20 ou plus.

1. Ouvrir un terminal dans `backend/`
2. `npm install`
3. `npm start`
4. Ouvrir `http://localhost:3000`

Le serveur Node sert à la fois l’API et le frontend. SQLite crée automatiquement `backend/madazon.db`.

Avant une mise en production : définir une vraie variable `JWT_SECRET`.
Le paiement réel n’est pas encore intégré.
