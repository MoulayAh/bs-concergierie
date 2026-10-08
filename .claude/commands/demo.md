---
description: Repetition de la demo - contrat, caution, etat des lieux, liberation, puis tentatives de casse
---

Prepare et verifie le scenario de demo de soutenance :

1. Verifie que `scripts/demo_scenario.py` existe ; sinon delegue a **backend-dev** sa creation : un script qui, via le client HTTP de l'API, deroule :
   creation du contrat -> signatures -> depot de 2 500 000 centimes -> depart -> rapport de retour + photos -> double signature -> RELEASED,
   en affichant chaque transition et le hash du rapport.
2. Ajoute a la suite 5 tentatives de casse en direct (montant negatif, .exe renomme .jpg, annulation pendant INSPECTION_PENDING, double liberation, signature de la mauvaise partie) qui doivent toutes renvoyer une erreur propre.
3. Lance-le contre la base de dev et rapporte le resultat. Signale tout ce qui n'est pas parfaitement propre a l'ecran.
