"""Verification hors ligne d'une quittance de liberation.

    python scripts/verify_receipt.py <receipt.json> [--events events.json] --server-key <b64>

La logique vit dans app/security/receipt_verify.py, partagee avec les tests.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.security.receipt_verify import ReceiptInvalid, main, verify_receipt

__all__ = ["ReceiptInvalid", "main", "verify_receipt"]

if __name__ == "__main__":
    sys.exit(main())
