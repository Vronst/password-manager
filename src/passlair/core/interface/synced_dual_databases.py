from typing import cast
from itertools import chain
from collections.abc import Iterable
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session, UOWTransaction
from ...dataclasses.facade_result import FacadeResult
from ...base.abstract.base_facade import BaseFacade
from ..database.database_manager import DatabaseManager, db
from ..models.base.base import Base
from ..models.standard_user import StandardUser
from ..models.vault_entry import VaultEntry


class SyncedDualDatabases(BaseFacade):
    """Allows for one local and one remote synced database.

    Creates/uses shared across library database, and
    connects to remote mariadb via provied params, syncing it
    to the local one. Allowing local storage with backup online.
    """

    # TODO
    vault_entry_fields: list[str] = []
    standard_user_fields: list[str] = []

    def __init__(
        self,
        sqlite_path: str,
        /,
        *,
        username: str | None = None,
        password: str | None = None,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
        full_url: str | None = None
    ) -> None:
        if not full_url and not all([username, password, host, port, database]):
            raise ValueError("Params for mariadb incomplete.")

        self.sqlite: DatabaseManager = db
        self.sqlite.init_sqlite(sqlite_path)

        self.mariadb: DatabaseManager = DatabaseManager()
        self.mariadb.init_mariadb(
            full_url,
            username=username,
            password=password,
            host=host,
            port=port,
            database=database
        )

        self.to_sync: dict[str, dict[str, str]] = {}

        event.listen(self.sqlite.session_factory, 'after_flush', self._add_to_sync)
        event.listen(self.sqlite.session_factory, 'after_commit', self._commit_sync)

    def sync_remote(self) -> FacadeResult:
        raise NotImplementedError  # TODO

    def _commit_sync(self, session: Session) -> None:
        pending = cast(
            "dict[str, dict[str, str]] | None", session.info.pop("pending_sync", None)
        )
        if pending:
            self.to_sync.update(pending)

    def _add_to_sync(self, session: Session, _: UOWTransaction) -> None:
        storage = session.info
        storage.setdefault("pending_sync", {})
        pending = cast(dict[str, dict[str, str]], storage['pending_sync'])
        identities = chain(session.new, session.dirty)
        # Instance State
        for instance in cast(Iterable[object], identities):
            if not isinstance(instance, Base):
                continue

            fields, model = self._get_model_and_fields(instance)
            inspection = inspect(instance).attrs
            wraped_instance_id = inspection['id'].history.unchanged
            assert wraped_instance_id
            instance_id = cast(str, wraped_instance_id[0])
            for field in fields:
                _history = inspection[field].history
                if not _history.has_changes():
                   continue

                assert _history.added
                key = f"{model}:{instance_id}"
                pending.setdefault(key, {})[field] = _history.added[0]

    def _get_model_and_fields(self, instance: Base) -> tuple[list[str], str]:
        if isinstance(instance, VaultEntry):
            return self.vault_entry_fields, 'vault_entry'

        elif isinstance(instance, StandardUser):
            return self.standard_user_fields, 'standard_user'

        raise NotImplementedError  # TODO
