"""F4 : chaine de hachage des evenements (domaine pur). Interfaces supposees : tests/fixtures/release.py."""

import copy
import hashlib
import uuid

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.fixtures.release import EVENT_FIELDS, GENESIS, LIFECYCLE_SPECS, build_chain, canonical, chain_hash


def _chain(n: int = 8) -> list[dict]:
    return build_chain(str(uuid.uuid4()), LIFECYCLE_SPECS[:n])


def _module():
    from app.domain import event_chain

    return event_chain


def test_genesis_is_64_zeros():
    assert _module().GENESIS == "0" * 64


def test_compute_event_hash_matches_the_plan_formula():
    event = _chain(1)[0]
    fields = {k: event[k] for k in EVENT_FIELDS}

    digest = _module().compute_event_hash(GENESIS, fields)

    assert digest == hashlib.sha256(GENESIS.encode() + b":" + canonical(fields)).hexdigest()
    assert digest == event["event_hash"]
    assert len(digest) == 64


def test_compute_event_hash_ignores_key_order():
    event = _chain(1)[0]
    fields = {k: event[k] for k in EVENT_FIELDS}
    reordered = dict(reversed(list(fields.items())))

    assert _module().compute_event_hash(GENESIS, fields) == _module().compute_event_hash(GENESIS, reordered)


@pytest.mark.parametrize("field", EVENT_FIELDS)
def test_compute_event_hash_depends_on_every_field(field):
    event = _chain(2)[1]
    fields = {k: event[k] for k in EVENT_FIELDS}
    altered = {**fields, field: 99 if field == "seq" else "autre"}

    assert _module().compute_event_hash(event["prev_hash"], fields) != _module().compute_event_hash(
        event["prev_hash"], altered
    )


def test_compute_event_hash_depends_on_previous_hash():
    event = _chain(2)[1]
    fields = {k: event[k] for k in EVENT_FIELDS}

    assert _module().compute_event_hash("a" * 64, fields) != _module().compute_event_hash("b" * 64, fields)


def test_compute_event_hash_accepts_null_status_and_payload_hash():
    fields = dict.fromkeys(EVENT_FIELDS) | {"seq": 1, "event": "create", "to_status": "DRAFT"}

    assert chain_hash(GENESIS, fields) == _module().compute_event_hash(GENESIS, fields)


def test_verify_chain_accepts_valid_chain_and_empty_chain():
    assert _module().verify_chain(_chain(8)) is None
    assert _module().verify_chain([]) is None


@pytest.mark.parametrize("length", [1, 2, 5, 8])
def test_verify_chain_accepts_chain_of_any_length(length):
    assert _module().verify_chain(_chain(length)) is None


def test_verify_chain_rejects_removed_middle_event():
    events = _chain()
    del events[3]

    with pytest.raises(_module().EventChainError):
        _module().verify_chain(events)


def test_verify_chain_rejects_removed_first_event():
    with pytest.raises(_module().EventChainError):
        _module().verify_chain(_chain()[1:])


def test_verify_chain_accepts_a_truncated_tail_but_the_length_is_checked_elsewhere():
    # Un prefixe est une chaine valide : c'est la quittance (length + head) qui detecte la troncature.
    assert _module().verify_chain(_chain()[:5]) is None


def test_verify_chain_rejects_reordered_events():
    events = _chain()
    events[2], events[3] = events[3], events[2]

    with pytest.raises(_module().EventChainError):
        _module().verify_chain(events)


def test_verify_chain_rejects_duplicated_event():
    events = _chain()
    events.insert(3, copy.deepcopy(events[2]))

    with pytest.raises(_module().EventChainError):
        _module().verify_chain(events)


def test_verify_chain_rejects_first_event_not_linked_to_genesis():
    events = _chain()
    events[0]["prev_hash"] = "f" * 64

    with pytest.raises(_module().EventChainError):
        _module().verify_chain(events)


def test_verify_chain_rejects_seq_gap_even_with_consistent_hashes():
    events = _chain(3)
    events[2]["seq"] = 4
    events[2]["event_hash"] = chain_hash(events[2]["prev_hash"], events[2])

    with pytest.raises(_module().EventChainError):
        _module().verify_chain(events)


def test_verify_chain_rejects_recomputed_hash_that_does_not_match_the_link():
    events = _chain(4)
    events[1]["payload_hash"] = "e" * 64
    events[1]["event_hash"] = chain_hash(events[1]["prev_hash"], events[1])

    with pytest.raises(_module().EventChainError):
        _module().verify_chain(events)


@settings(max_examples=40, deadline=None)
@given(
    index=st.integers(min_value=0, max_value=7),
    field=st.sampled_from(EVENT_FIELDS),
    junk=st.one_of(st.text(max_size=20), st.integers(), st.none()),
)
def test_verify_chain_detects_any_altered_field(index, field, junk):
    events = _chain(8)
    if events[index][field] == junk:
        return
    events[index][field] = junk

    with pytest.raises(_module().EventChainError):
        _module().verify_chain(events)


@settings(max_examples=30, deadline=None)
@given(index=st.integers(min_value=0, max_value=7), digest=st.text(alphabet="0123456789abcdef", max_size=64))
def test_verify_chain_detects_altered_links(index, digest):
    events = _chain(8)
    for key in ("prev_hash", "event_hash"):
        mutated = copy.deepcopy(events)
        if mutated[index][key] == digest:
            continue
        mutated[index][key] = digest
        with pytest.raises(_module().EventChainError):
            _module().verify_chain(mutated)
