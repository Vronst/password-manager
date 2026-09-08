from typing import TYPE_CHECKING
import logging
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Generator

from pydantic import ValidationError
from sqlalchemy import MetaData, create_engine, make_url, URL
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from ..models.base import Base
from ...dataclasses.db_connection import DBConnection

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine
    from sqlalchemy.orm import scoped_session


class DatabaseManager:
    def __init__(self) -> None:
        self._engine: None | Engine = None
        self._session_factory: None | scoped_session[Session] = None

    @property
    def session_factory(self) -> scoped_session[Session] | None:
        return self._session_factory

    def _reinit_check(self, force: bool = False) -> bool:
        if not self._engine:
            return True

        if not force:
            return False

        self.dispose()
        return True

    @staticmethod
    def _mariadb_url(
        *,
        full_url: str | URL | None = None,
        username: str | None = None,
        password: str | None = None,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
    ) -> URL:
        """Builds and validates a MariaDB connection URL.

        Accepts either a ready ``full_url`` or the discrete components, and
        defers the "one form or the other must be complete" check to
        DBConnection. Pydantic's ValidationError is translated into a plain
        ValueError with a readable message.
        """
        if isinstance(full_url, URL):
            return full_url

        if full_url is not None:
            return make_url(full_url)

        try:
            conn = DBConnection(
                username=username,
                password=password,
                host=host,
                port=port,
                database=database,
            )
        except ValidationError as e:
            raise ValueError(f"Invalid MariaDB connection config: {e}") from e

        if conn.full_url is None:  # DBConnection's validator guarantees otherwise
            raise RuntimeError("DBConnection produced no URL")

        return make_url(conn.full_url)

    def __create_sqlite_url(self, path: str | None = None) -> str:
        filepath = path or str(Path(__file__).parents[4] / "passLair_db.db")
        return f"sqlite:///{filepath}"

    def init_sqlite(self, filepath: str | None = None, *, force: bool = False) -> None:
        """Initializes a local SQLite database configuration."""
        if not self._reinit_check(force):
            logger.debug(
                "init_sqlite: already initialized, skipping re-init (force=False)"
            )
            return

        database_url = self.__create_sqlite_url(filepath)
        logger.info("init_sqlite: initializing database at %s", filepath)

        self._engine = create_engine(
            database_url, connect_args={"check_same_thread": False}
        )
        self._setup_factory()
        self.create_tables(Base.metadata)

    def init_mariadb(
        self,
        full_url: str | URL | None = None,
        *,
        username: str | None = None,
        password: str | None = None,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
        force: bool = False,
    ) -> None:
        """Initializes a networked MariaDB connection using the pymysql driver.

        Pass either ``full_url`` (a connection URL or SQLAlchemy ``URL``), or
        all of ``username`` / ``password`` / ``host`` / ``port`` / ``database``.
        A caller holding a config dict can spread it: ``init_mariadb(**cfg)``.

        Raises:
            ValueError: if neither form is fully supplied.
        """
        # URL Format: mariadb+pymysql://user:pass@host:port/dbname
        if not self._reinit_check(force):
            logger.debug(
                "init_mariadb: already initialized, skipping re-init (force=False)"
            )
            return

        database_url = self._mariadb_url(
            full_url=full_url,
            username=username,
            password=password,
            host=host,
            port=port,
            database=database,
        )
        # Never log the URL directly -- it embeds the password. We read only
        # the non-secret parts of the parsed URL here.
        logger.info(
            "init_mariadb: connecting to %s:%s/%s as %s",
            database_url.host,
            database_url.port,
            database_url.database,
            database_url.username,
        )

        self._engine = create_engine(
            database_url,
            pool_size=10,  # Keeps up to 10 connections open
            max_overflow=20,  # Can spawn 20 extra if traffic spikes
            pool_recycle=3600,  # Recycles connections every hour to prevent timeouts
            pool_pre_ping=True,  # Checks if connection is alive before issuing queries
        )
        self._setup_factory()
        self.create_tables(Base.metadata)

    def _setup_factory(self) -> None:
        """Internal helper to tie the engine to the session factories."""
        local_factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self._engine,
            expire_on_commit=False,
        )
        # scoped_session ensures thread-safety across your library
        self._session_factory = scoped_session(local_factory)

    def create_tables(self, base_metadata: MetaData) -> None:
        """Utility to generate the database schema tables if they don't exist yet."""
        if self._engine is None:
            raise RuntimeError(
                "DatabaseManager must be initialized before creating tables."
            )
        base_metadata.create_all(bind=self._engine)

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """
        Context manager providing a secure scope for database operations.
        Automatically commits changes or rolls back transactions on failure.
        """
        if self._session_factory is None:
            raise RuntimeError(
                "DatabaseManager is not initialized. Call init_sqlite or init_mariadb first."
            )

        db_session: Session = self._session_factory()
        try:
            yield db_session
            db_session.commit()
        except Exception:
            logger.exception("session: transaction raised, rolling back")
            db_session.rollback()
            raise
        finally:
            db_session.close()
            self._session_factory.remove()

    def dispose(self) -> None:
        """Releases the engine's connection pool and the scoped session, and
        resets the manager to its uninitialized state."""
        if self._session_factory:
            self._session_factory.remove()

        if self._engine:
            self._engine.dispose()

        self._engine = None
        self._session_factory = None


db = DatabaseManager()
