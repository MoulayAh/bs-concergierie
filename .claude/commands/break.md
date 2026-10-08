---
description: Red team - essayer de casser l'application comme le correcteur
argument-hint: [zone - montants | uploads | flux | acces | concurrence | tout]
---

Zone ciblee : $ARGUMENTS (si vide : tout)

Delegue a **adversarial-tester** l'attaque de cette zone. Puis :
- lance `python -m pytest tests/adversarial -q` ;
- liste les FAILLES trouvees (tests rouges) avec leur gravite ;
- propose de les envoyer a backend-dev. **Ne corrige rien sans mon accord.**
