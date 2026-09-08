import logging
from datetime import datetime

from ...base.abstract.authenticated_user import AuthenticatedUser
from ...base.abstract.base_repository import BaseRepository
from ...dataclasses.password_data import PasswordCreation
from ..crypto import decrypt, encrypt
from ..database.database_manager import db
from ..models.vault_entry import VaultEntry

logger = logging.getLogger(__name__)


class PasswordWriter(BaseRepository):
    def __init__(self, user: AuthenticatedUser) -> None:
        self.user: AuthenticatedUser = AuthenticatedUser.require(user)

    def save_password(self, service: str, login: str, password: str) -> bool:
        data = self._prepare_data(service, login, password)
        entry = self._add_or_update(data)

        with db.session() as session:
            session.add(entry)

        logger.info(
            "save_password: saved entry for service=%r, user_id=%r",
            service,
            self.user.user_id,
        )
        return True

    def save_passwords(self, passwords: dict[str, dict[str, str]]) -> None:
        """Imports a batch of {service: {"login": ..., "password": ...}} entries
        for the logged-in user in a single transaction -- the same shape
        Exporter._retrieve_passwords/export_to_json produce, so a round-trip
        needs no reshaping.

        For each entry: a new service is inserted; an existing service whose
        login/password are unchanged is left untouched; an existing service
        whose login or password differs is updated in place.
        """
        dek = self.user.get_session_key()
        with db.session() as session:
            existing = {
                e.service_name: e
                for e in session.query(VaultEntry)
                .filter_by(user_id=self.user.user_id)
                .filter(VaultEntry.deleted_at.is_(None))
                .all()
            }
            for service, credentials in passwords.items():
                login = credentials["login"]
                plain_password = credentials["password"]
                entry = existing.get(service)

                if entry is not None and self._is_unchanged(
                    entry, login, plain_password, dek
                ):
                    logger.debug(
                        "save_passwords: unchanged, skipping service=%r (user_id=%r)",
                        service,
                        self.user.user_id,
                    )
                    continue

                ready_data = self._prepare_data(service, login, plain_password)
                if entry is None:
                    session.add(self._new_password(ready_data))
                else:
                    _ = self._update_password(ready_data, entry)

        logger.info(
            "save_passwords: imported %d entries for user_id=%r",
            len(passwords),
            self.user.user_id,
        )

    def _is_unchanged(
        self, entry: VaultEntry, login: str, password: str, dek: bytes
    ) -> bool:
        """True if `entry` already holds this exact login/password.

        Requires decrypting `entry.password` -- ciphertext alone can never
        answer this, since encryption uses a fresh nonce on every call (see
        core.crypto.encrypt), so re-encrypting an identical plaintext never
        reproduces the same bytes.
        """
        if entry.login != login:
            return False

        current_password = decrypt(entry.password, entry.nonce, dek).decode("utf-8")
        return current_password == password

    def _prepare_data(
        self, service: str, login: str, password: str
    ) -> PasswordCreation:
        # get_session_key() raises PermissionError itself when there's no
        # active session -- it never returns None, so callers must catch
        # PermissionError rather than expect a ValueError here.
        dek = self.user.get_session_key()

        if service == "" or login == "" or password == "":
            logger.warning(
                "_prepare_data: rejected empty service/login/password (user_id=%r)",
                self.user.user_id,
            )
            raise ValueError("Service name, login and password must not be empty")

        encrypted_password, nonce = self._encrypt_password(password, dek)
        assert isinstance(self.user.user_id, str)  # for linting
        return PasswordCreation(
            user_id=self.user.user_id,
            service_name=service,
            login=login,
            password=encrypted_password,
            nonce=nonce,
        )

    def _add_or_update(self, data: PasswordCreation) -> VaultEntry:
        entry = self._fetch_row(
            VaultEntry,
            filters={
                "service_name": data.service_name,
                "user_id": self.user.user_id,
            },
        )
        if entry is None:
            new_entry = self._new_password(data)
        else:
            new_entry = self._update_password(data, entry)

        return new_entry

    def _update_password(self, data: PasswordCreation, entry: VaultEntry) -> VaultEntry:
        entry.password = data.password
        entry.login = data.login
        entry.nonce = data.nonce
        return entry

    def _new_password(self, data: PasswordCreation) -> VaultEntry:
        new_pass = VaultEntry(**data.model_dump())
        return new_pass

    def _encrypt_password(self, password: str, dek: bytes) -> tuple[bytes, bytes]:
        return encrypt(password.encode("utf-8"), dek)

    def delete_password(self, service: str) -> None:
        _ = self.user.get_session_key()

        with db.session() as session:
            entry = (
                session.query(VaultEntry)
                .filter_by(user_id=self.user.user_id, service_name=service)
                .filter(VaultEntry.deleted_at.is_(None))
                .first()
            )
            if entry is None:
                logger.warning(
                    "delete_password: no live entry for service=%r (user_id=%r)",
                    service,
                    self.user.user_id,
                )
                raise ValueError(f"Service {service} not found.")

            entry.deleted_at = datetime.now()

        logger.info(
            "delete_password: soft-deleted entry for service=%r, user_id=%r",
            service,
            self.user.user_id,
        )
