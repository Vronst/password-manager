from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine as real_create_engine

from passlair.core.interface.synced_dual_databases import SyncedDualDatabases
from passlair.core.models.standard_user import StandardUser
from passlair.core.models.vault_entry import VaultEntry

CREATE_ENGINE_TARGET = "passlair.core.database.database_manager.create_engine"


def _fake_create_engine(url, *args, **kwargs):
    """Lets the local SQLite side build a real engine (so flush/commit events
    actually fire) while faking out the MariaDB side, which would otherwise
    try to open a real network connection during __init__/create_tables."""
    if str(url).startswith("sqlite"):
        return real_create_engine(url, *args, **kwargs)
    return MagicMock()


@pytest.fixture
def synced() -> SyncedDualDatabases:
    """A SyncedDualDatabases wired to a real in-memory SQLite (so ORM events
    genuinely fire) and a faked-out MariaDB side (no real connection)."""
    with patch(CREATE_ENGINE_TARGET, side_effect=_fake_create_engine):
        instance = SyncedDualDatabases(
            ":memory:",
            username="vronst",
            password="pw",
            host="127.0.0.1",
            port=3306,
            database="passlair",
        )
    # vault_entry_fields/standard_user_fields ship empty (# TODO in the
    # source) -- a real caller is expected to configure which columns sync.
    instance.vault_entry_fields = ["service_name", "login"]
    instance.standard_user_fields = ["username", "email"]
    return instance


def _make_vault_entry(**overrides: object) -> VaultEntry:
    defaults: dict[str, object] = {
        "user_id": "user-1",
        "service_name": "github.com",
        "login": "octocat",
        "password": b"ciphertext",
        "nonce": b"n" * 12,
    }
    defaults.update(overrides)
    return VaultEntry(**defaults)  # type: ignore[arg-type]


class TestPositive:
    def test_constructor_accepts_full_component_set(self, synced: SyncedDualDatabases):
        """Regression test: __init__'s own MariaDB-completeness check used to
        be inverted and raised ValueError for exactly this, valid, call."""
        assert isinstance(synced, SyncedDualDatabases)

    def test_new_instance_is_captured_on_commit(self, synced: SyncedDualDatabases):
        """session.new (a freshly inserted row) must end up in to_sync, not
        just session.dirty (previously-persisted rows that were edited)."""
        with synced.sqlite.session() as session:
            entry = _make_vault_entry()
            session.add(entry)
        entry_id = entry.id

        key = f"vault_entry:{entry_id}"
        assert synced.to_sync[key] == {
            "service_name": "github.com",
            "login": "octocat",
        }

    def test_dirty_instance_field_change_is_captured(self, synced: SyncedDualDatabases):
        with synced.sqlite.session() as session:
            entry = _make_vault_entry()
            session.add(entry)
        entry_id = entry.id

        with synced.sqlite.session() as session:
            stored = session.get(VaultEntry, entry_id)
            assert stored is not None
            stored.login = "someone-else"

        key = f"vault_entry:{entry_id}"
        assert synced.to_sync[key]["login"] == "someone-else"

    def test_unrelated_field_change_does_not_pollute_entry(
        self, synced: SyncedDualDatabases
    ):
        """Only fields actually listed in vault_entry_fields should be
        tracked -- mutating user_id (not in the allowlist) must not appear."""
        with synced.sqlite.session() as session:
            entry = _make_vault_entry()
            session.add(entry)
        entry_id = entry.id
        synced.to_sync.clear()

        with synced.sqlite.session() as session:
            stored = session.get(VaultEntry, entry_id)
            assert stored is not None
            stored.user_id = "user-2"

        key = f"vault_entry:{entry_id}"
        assert key not in synced.to_sync or synced.to_sync[key] == {}

    def test_two_changed_fields_in_one_flush_both_recorded(
        self, synced: SyncedDualDatabases
    ):
        """Guards against the earlier bug where writing pending[key] = {...}
        for each field clobbered the previous field's entry."""
        with synced.sqlite.session() as session:
            entry = _make_vault_entry()
            session.add(entry)
        entry_id = entry.id

        with synced.sqlite.session() as session:
            stored = session.get(VaultEntry, entry_id)
            assert stored is not None
            stored.login = "new-login"
            stored.service_name = "gitlab.com"

        key = f"vault_entry:{entry_id}"
        assert synced.to_sync[key] == {
            "login": "new-login",
            "service_name": "gitlab.com",
        }

    def test_two_instances_same_model_do_not_clobber_each_other(
        self, synced: SyncedDualDatabases
    ):
        with synced.sqlite.session() as session:
            first = _make_vault_entry(service_name="github.com")
            second = _make_vault_entry(service_name="gitlab.com")
            session.add(first)
            session.add(second)
        first_id, second_id = first.id, second.id

        assert synced.to_sync[f"vault_entry:{first_id}"]["service_name"] == "github.com"
        assert synced.to_sync[f"vault_entry:{second_id}"]["service_name"] == "gitlab.com"

    def test_earlier_transaction_fields_survive_a_later_partial_update(
        self, synced: SyncedDualDatabases
    ):
        """to_sync accumulates across transactions until sync_remote drains
        it -- a later commit that only touches one field must not erase
        fields recorded by an earlier commit for the same row."""
        with synced.sqlite.session() as session:
            entry = _make_vault_entry()
            session.add(entry)
        entry_id = entry.id

        with synced.sqlite.session() as session:
            stored = session.get(VaultEntry, entry_id)
            assert stored is not None
            stored.login = "second-login"

        key = f"vault_entry:{entry_id}"
        assert synced.to_sync[key] == {
            "service_name": "github.com",
            "login": "second-login",
        }

    def test_standard_user_model_is_also_captured(self, synced: SyncedDualDatabases):
        with synced.sqlite.session() as session:
            user = StandardUser(
                username="vronst",
                email="vronst@example.com",
                master_password=b"x" * 32,
                salt=b"s" * 16,
                dek=b"d" * 32,
                dek_nonce=b"n" * 12,
                backup_dek=b"b" * 32,
                backup_dek_nonce=b"m" * 12,
            )
            session.add(user)
        user_id = user.id

        key = f"standard_user:{user_id}"
        assert synced.to_sync[key] == {
            "username": "vronst",
            "email": "vronst@example.com",
        }


class TestNegative:
    def test_constructor_rejects_incomplete_component_set(self):
        with patch(CREATE_ENGINE_TARGET, side_effect=_fake_create_engine):
            with pytest.raises(ValueError, match="Params for mariadb incomplete"):
                SyncedDualDatabases(":memory:", username="vronst")

    def test_unmodified_flush_records_nothing(self, synced: SyncedDualDatabases):
        """Merely loading and re-saving a row with no actual attribute
        change must not produce a pending_sync entry."""
        with synced.sqlite.session() as session:
            entry = _make_vault_entry()
            session.add(entry)
        entry_id = entry.id
        synced.to_sync.clear()

        with synced.sqlite.session() as session:
            stored = session.get(VaultEntry, entry_id)
            assert stored is not None
            stored.login = stored.login  # touch, but no real change

        assert synced.to_sync == {}
