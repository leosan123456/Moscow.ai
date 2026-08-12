"""Repositórios SQL do backoffice (`User`, `Membership`, `Subscription`, `ApiKey`,
`Session`, `Client`)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from vulnai_shared.models import Client
from vulnai_backoffice.entitlements import Subscription
from vulnai_backoffice.models import ApiKey, Membership
from vulnai_backoffice.models import Session as BackofficeSession
from vulnai_backoffice.models import User
from vulnai_persistence.orm import (
    ApiKeyRow,
    ClientRow,
    MembershipRow,
    SessionRow,
    SubscriptionRow,
    UserRow,
)


class SqlUserRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def get(self, user_id: str) -> User | None:
        with self._sessions() as session:
            row = session.get(UserRow, user_id)
            return User.model_validate(row.payload) if row else None

    def get_by_email(self, email: str) -> User | None:
        with self._sessions() as session:
            row = session.scalar(select(UserRow).where(UserRow.email == email.strip().lower()))
            return User.model_validate(row.payload) if row else None

    def save(self, user: User) -> User:
        with self._sessions() as session:
            row = session.get(UserRow, user.id)
            payload = user.model_dump(mode="json")
            if row is None:
                session.add(UserRow(id=user.id, email=user.email, payload=payload))
            else:
                row.email = user.email
                row.payload = payload
            session.commit()
        return user


class SqlMembershipRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def list_for_user(self, user_id: str) -> list[Membership]:
        with self._sessions() as session:
            rows = session.scalars(
                select(MembershipRow).where(MembershipRow.user_id == user_id)
            ).all()
            return [Membership.model_validate(row.payload) for row in rows]

    def list_for_client(self, client_id: str) -> list[Membership]:
        with self._sessions() as session:
            rows = session.scalars(
                select(MembershipRow).where(MembershipRow.client_id == client_id)
            ).all()
            return [Membership.model_validate(row.payload) for row in rows]

    def get(self, membership_id: str) -> Membership | None:
        with self._sessions() as session:
            row = session.get(MembershipRow, membership_id)
            return Membership.model_validate(row.payload) if row else None

    def save(self, membership: Membership) -> Membership:
        with self._sessions() as session:
            session.merge(
                MembershipRow(
                    id=membership.id,
                    user_id=membership.user_id,
                    client_id=membership.client_id,
                    scope=membership.scope.value,
                    payload=membership.model_dump(mode="json"),
                )
            )
            session.commit()
        return membership


class SqlSubscriptionRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def get_for_client(self, client_id: str) -> Subscription | None:
        with self._sessions() as session:
            row = session.get(SubscriptionRow, client_id)
            return Subscription.model_validate(row.payload) if row else None

    def save(self, subscription: Subscription) -> Subscription:
        with self._sessions() as session:
            session.merge(
                SubscriptionRow(
                    client_id=subscription.client_id, payload=subscription.model_dump(mode="json")
                )
            )
            session.commit()
        return subscription


class SqlApiKeyRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def get_by_key_id(self, key_id: str) -> ApiKey | None:
        with self._sessions() as session:
            row = session.get(ApiKeyRow, key_id)
            return ApiKey.model_validate(row.payload) if row else None

    def save(self, api_key: ApiKey) -> ApiKey:
        with self._sessions() as session:
            session.merge(
                ApiKeyRow(
                    key_id=api_key.key_id,
                    client_id=api_key.client_id,
                    membership_id=api_key.membership_id,
                    payload=api_key.model_dump(mode="json"),
                )
            )
            session.commit()
        return api_key

    def list_for_client(self, client_id: str) -> list[ApiKey]:
        with self._sessions() as session:
            rows = session.scalars(select(ApiKeyRow).where(ApiKeyRow.client_id == client_id)).all()
            return [ApiKey.model_validate(row.payload) for row in rows]


class SqlSessionRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def get_by_token_hash(self, token_hash: str) -> BackofficeSession | None:
        with self._sessions() as session:
            row = session.get(SessionRow, token_hash)
            return BackofficeSession.model_validate(row.payload) if row else None

    def save(self, session_: BackofficeSession) -> BackofficeSession:
        with self._sessions() as session:
            session.merge(
                SessionRow(
                    token_hash=session_.token_hash,
                    user_id=session_.user_id,
                    payload=session_.model_dump(mode="json"),
                )
            )
            session.commit()
        return session_


class SqlClientRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def get(self, client_id: str) -> Client | None:
        with self._sessions() as session:
            row = session.get(ClientRow, client_id)
            return Client.model_validate(row.payload) if row else None

    def save(self, client: Client) -> Client:
        with self._sessions() as session:
            session.merge(
                ClientRow(id=client.id, name=client.name, payload=client.model_dump(mode="json"))
            )
            session.commit()
        return client

    def list_all(self) -> list[Client]:
        with self._sessions() as session:
            rows = session.scalars(select(ClientRow)).all()
            return [Client.model_validate(row.payload) for row in rows]
