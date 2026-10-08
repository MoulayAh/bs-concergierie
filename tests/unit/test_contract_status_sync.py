"""Reserve 1 : les trois copies de ContractStatus (domaine, modeles, migration) doivent rester identiques.

Un ecart provoquerait un ValueError dans le service, donc un 500.
"""

import importlib.util
from pathlib import Path
from types import ModuleType

from app.domain.state_machine import ContractStatus as DomainStatus
from app.models.enums import ContractStatus as ModelStatus

MIGRATION = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "20261008_0001_initial_f1.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0001_initial_f1", MIGRATION)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_contract_status_values_are_identical_in_domain_models_and_migration():
    domain = {s.value for s in DomainStatus}
    models = {s.value for s in ModelStatus}
    migration = set(_load_migration().CONTRACT_STATUSES)

    assert domain == models == migration


def test_contract_status_names_match_values_in_domain_and_models():
    assert {s.name: s.value for s in DomainStatus} == {s.name: s.value for s in ModelStatus}


def test_migration_contract_statuses_have_no_duplicates():
    statuses = _load_migration().CONTRACT_STATUSES

    assert len(statuses) == len(set(statuses))
