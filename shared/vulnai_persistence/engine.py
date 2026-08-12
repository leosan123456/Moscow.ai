"""Engine e sessão SQLAlchemy.

Direcionado a PostgreSQL em produção (ver `tech_stack` do projeto), mas funciona sobre
qualquer dialeto suportado pelo SQLAlchemy. Os testes deste repositório rodam contra
SQLite porque este ambiente de desenvolvimento não tem um servidor Postgres disponível —
por isso o esquema (`vulnai_persistence.orm`) usa só `sqlalchemy.JSON` genérico, nunca um
tipo específico de dialeto (`JSONB`, `ARRAY`), para que o mesmo código funcione nos dois.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from vulnai_persistence.orm import Base


def build_engine(url: str, *, echo: bool = False) -> Engine:
    """Cria o engine. Para SQLite em arquivo/memória, desliga a checagem de thread —
    os repositórios abrem uma sessão curta por chamada e podem rodar de threads diferentes."""
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, echo=echo, future=True, connect_args=connect_args)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def create_all(engine: Engine) -> None:
    """Cria o esquema. Uso local/teste — em produção o esquema vem de migração Alembic."""
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transação manual, para o chamador que precisa agrupar mais de uma escrita."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
