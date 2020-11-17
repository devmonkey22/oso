"""SQLAlchemy hooks that enable oso on SQLAlchemy operations."""
import functools
from typing import Any, Callable

from sqlalchemy.event import listen, remove
from sqlalchemy.orm.query import Query
from sqlalchemy.orm import aliased, sessionmaker

from oso import Oso

from sqlalchemy_oso.auth import authorize_model, authorize_model_filter

def enable_hooks(get_oso: Callable[[], Oso],
                 get_user: Callable[[], Any],
                 get_action: Callable[[], Any],
                 target=None):
    """Enable all SQLAlchemy hooks."""
    if target is None:
        target = Query

    disable_before_compile = enable_before_compile(target, get_oso, get_user, get_action)

    def disable_hooks():
        disable_before_compile()

    return disable_hooks

def enable_before_compile(target, get_oso: Callable[[], Oso], get_user: Callable[[], Any], get_action: Callable[[], Any]):
    """Enable before compile hook."""
    auth = functools.partial(
        authorize_query,
        get_oso=get_oso,
        get_user=get_user,
        get_action=get_action)

    listen(target, "before_compile", auth, retval=True)

    return lambda: remove(target, "before_compile", auth)

def authorize_query(query: Query, get_oso, get_user, get_action) -> Query:
    oso = get_oso()
    actor = get_user()
    action = get_action()

    entities = {column['entity'] for column in query.column_descriptions}
    for entity in entities:
        # Only apply authorization to columns that represent a mapper entity.
        if entity is None:
            continue

        authorized_filter = authorize_model_filter(
            oso,
            actor,
            action,
            query.session,
            entity)
        if authorized_filter is not None:
            query = query.filter(authorized_filter)

    return query


def make_authorized_query_cls(get_oso, get_user, get_action) -> Query:
    class AuthorizedQuery(Query):
        """Query object that always applies authorization for ORM entities."""

    enable_hooks(get_oso, get_user, get_action, target=AuthorizedQuery)

    return AuthorizedQuery


def authorized_sessionmaker(
    get_oso,
    get_user,
    get_action,
    *args,
    **kwargs
):
    """Session factory for sessions with oso authorization applied.

    :param get_oso: Callable that return oso instance to use for authorization.
    :param get_user: Callable that returns user for an authorization request.
    :param get_action: Callable that returns user for the action.

    The ``query_cls`` parameter cannot be used with ``authorize_sessionmaker``.

    Baked queries will be disabled for this session, because they are incompatible
    with authorization.

    All other positional and keyword arguments are passed through to
    :py:func:`sqlalchemy.orm.session.sessionmaker` unchanged.
    """
    # TODO (dhatch): Should be possible with additional wrapping.
    assert 'query_cls' not in kwargs, "Cannot use custom query class with authorized_sessionmaker."
    assert 'enable_baked_queries' not in kwargs, "Cannot set enabled_baked_queries."
    return sessionmaker(
        query_cls=make_authorized_query_cls(
            get_oso,
            get_user,
            get_action
        ),
        enable_baked_queries=False,
        *args,
        **kwargs)
