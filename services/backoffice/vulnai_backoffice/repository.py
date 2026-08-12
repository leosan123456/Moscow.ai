"""Repositórios do backoffice (protocolos + implementação em memória)."""

from __future__ import annotations

from typing import Protocol

from vulnai_shared.models import Client
from vulnai_backoffice.entitlements import Subscription
from vulnai_backoffice.models import ApiKey, Membership, Session, User


class UserRepository(Protocol):
    def get(self, user_id: str) -> User | None: ...
    def get_by_email(self, email: str) -> User | None: ...
    def save(self, user: User) -> User: ...


class MembershipRepository(Protocol):
    def list_for_user(self, user_id: str) -> list[Membership]: ...
    def list_for_client(self, client_id: str) -> list[Membership]: ...
    def get(self, membership_id: str) -> Membership | None: ...
    def save(self, membership: Membership) -> Membership: ...


class SubscriptionRepository(Protocol):
    def get_for_client(self, client_id: str) -> Subscription | None: ...
    def save(self, subscription: Subscription) -> Subscription: ...


class ApiKeyRepository(Protocol):
    def get_by_key_id(self, key_id: str) -> ApiKey | None: ...
    def save(self, api_key: ApiKey) -> ApiKey: ...
    def list_for_client(self, client_id: str) -> list[ApiKey]: ...


class SessionRepository(Protocol):
    def get_by_token_hash(self, token_hash: str) -> Session | None: ...
    def save(self, session: Session) -> Session: ...


class ClientRepository(Protocol):
    def get(self, client_id: str) -> Client | None: ...
    def save(self, client: Client) -> Client: ...
    def list_all(self) -> list[Client]: ...


class InMemoryUserRepository:
    def __init__(self, users: list[User] | None = None) -> None:
        self._by_id: dict[str, User] = {}
        self._by_email: dict[str, str] = {}
        for user in users or []:
            self.save(user)

    def get(self, user_id: str) -> User | None:
        return self._by_id.get(user_id)

    def get_by_email(self, email: str) -> User | None:
        user_id = self._by_email.get(email.strip().lower())
        return self._by_id.get(user_id) if user_id else None

    def save(self, user: User) -> User:
        self._by_id[user.id] = user
        self._by_email[user.email] = user.id
        return user


class InMemoryMembershipRepository:
    def __init__(self, memberships: list[Membership] | None = None) -> None:
        self._items: dict[str, Membership] = {m.id: m for m in (memberships or [])}

    def list_for_user(self, user_id: str) -> list[Membership]:
        return [m for m in self._items.values() if m.user_id == user_id]

    def list_for_client(self, client_id: str) -> list[Membership]:
        return [m for m in self._items.values() if m.client_id == client_id]

    def get(self, membership_id: str) -> Membership | None:
        return self._items.get(membership_id)

    def save(self, membership: Membership) -> Membership:
        self._items[membership.id] = membership
        return membership


class InMemorySubscriptionRepository:
    def __init__(self, subscriptions: list[Subscription] | None = None) -> None:
        self._by_client: dict[str, Subscription] = {
            s.client_id: s for s in (subscriptions or [])
        }

    def get_for_client(self, client_id: str) -> Subscription | None:
        return self._by_client.get(client_id)

    def save(self, subscription: Subscription) -> Subscription:
        self._by_client[subscription.client_id] = subscription
        return subscription


class InMemoryApiKeyRepository:
    def __init__(self, keys: list[ApiKey] | None = None) -> None:
        self._by_key_id: dict[str, ApiKey] = {k.key_id: k for k in (keys or [])}

    def get_by_key_id(self, key_id: str) -> ApiKey | None:
        return self._by_key_id.get(key_id)

    def save(self, api_key: ApiKey) -> ApiKey:
        self._by_key_id[api_key.key_id] = api_key
        return api_key

    def list_for_client(self, client_id: str) -> list[ApiKey]:
        return [k for k in self._by_key_id.values() if k.client_id == client_id]


class InMemorySessionRepository:
    def __init__(self) -> None:
        self._by_hash: dict[str, Session] = {}

    def get_by_token_hash(self, token_hash: str) -> Session | None:
        return self._by_hash.get(token_hash)

    def save(self, session: Session) -> Session:
        self._by_hash[session.token_hash] = session
        return session


class InMemoryClientRepository:
    def __init__(self, clients: list[Client] | None = None) -> None:
        self._items: dict[str, Client] = {c.id: c for c in (clients or [])}

    def get(self, client_id: str) -> Client | None:
        return self._items.get(client_id)

    def save(self, client: Client) -> Client:
        self._items[client.id] = client
        return client

    def list_all(self) -> list[Client]:
        return list(self._items.values())
