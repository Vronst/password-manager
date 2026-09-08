from unittest.mock import MagicMock, patch

import pytest

from passlair.core.auth.credentials import DEK_SIZE, SALT_SIZE
from passlair.core.auth.user_manager import UserManager
from passlair.core.crypto import NONCE_SIZE
from passlair.core.models.standard_user import StandardUser
from passlair.dataclasses.user_data import UserCreation


def build_mock_db_session() -> tuple[MagicMock, MagicMock]:
    """Builds a (mock_db, mock_session) pair whose db.session() context
    manager mirrors DatabaseManager.session()'s real exit behavior: commit
    on a clean exit (rolling back and re-raising if that commit itself
    fails), rollback on an exception from the body, never suppressing --
    since writers no longer call session.commit() themselves, the real
    context manager owns that now.

    Shared by the mock_db_session fixture below and by any test module that
    needs its own `db` mock (e.g. to also stub out a query chain) without
    re-deriving this exit behavior."""
    mock_session = MagicMock()

    def fake_exit(exc_type, exc_val, exc_tb):
        if exc_type is None:
            try:
                mock_session.commit()
            except Exception:
                mock_session.rollback()
                raise
        else:
            mock_session.rollback()
        # Never suppress -- an exception raised in the `with` body (or
        # by commit() above) must keep propagating.
        return False

    mock_db = MagicMock()
    mock_db.session.return_value.__enter__.return_value = mock_session
    mock_db.session.return_value.__exit__.side_effect = fake_exit
    return mock_db, mock_session


@pytest.fixture
def mock_db_session():
    """Fixture to cleanly abstract the context-managed DB session nesting."""
    mock_db, mock_session = build_mock_db_session()
    with patch("passlair.core.writers.user_writer.db", mock_db):
        yield mock_session, mock_db


@pytest.fixture
def mock_user_data():
    """Generates standard user data for validation tests."""
    return UserCreation(
        username="test_user",
        email="test@example.com",
        master_password=b"secure_password_hash",
        salt=b"random_salt",
        dek=b"encrypted_dek",
        dek_nonce=b"dek_nonce_12",
        backup_dek=b"encrypted_backup_dek",
        backup_dek_nonce=b"backup_dek_nonc",
    )


@pytest.fixture
def mock_user():
    """Generates StandarUser mock for tests.

    salt/dek/dek_nonce/backup_dek/backup_dek_nonce are sized correctly for
    real passlair_crypto (16/32/12/32/12 bytes respectively) but are
    otherwise arbitrary placeholders -- they don't decrypt to anything.
    Tests exercising verify_password/unwrap_dek/etc. should mock those
    functions at the point of use rather than relying on real crypto here
    (see test_change_password, test_verify_password) -- real crypto against
    this module's composition belongs in test_credentials.py/test_crypto.py,
    and real end-to-end roundtrips belong in the integration tests.
    """
    mock = MagicMock(spec=StandardUser)
    mock.id = "secret_id"
    mock.master_password = bytes([1] * 32)
    mock.salt = b"s" * SALT_SIZE
    mock.dek = b"d" * DEK_SIZE
    mock.dek_nonce = b"n" * NONCE_SIZE
    mock.backup_dek = b"b" * DEK_SIZE
    mock.backup_dek_nonce = b"m" * NONCE_SIZE
    return mock


@pytest.fixture
def mock_user_manager():
    """Mocks user-manager for unit testing."""
    mock = MagicMock(spec=UserManager)
    mock.get_session_key.return_value = "session_key"
    mock.user_id = "string_id"

    return mock
