"""Release Store connections at test teardown, including failed constructors.

Many older fixtures return a Store without closing it. SQLite connection cycles
can outlive those tests and exhaust the default 1024-descriptor limit. Track the
connections allocated by each test without changing product connection lifetime.
Tests that exercise explicit close/reopen still run the real close operations.
"""

from functools import wraps

import pytest

from shield.agent.store import Store


@pytest.fixture(autouse=True)
def close_test_stores(monkeypatch):
    connections = []
    initialize = Store.__init__

    @wraps(initialize)
    def track_connection(self, *args, **kwargs):
        try:
            initialize(self, *args, **kwargs)
        finally:
            connection = getattr(self, "conn", None)
            if connection is not None:
                connections.append(connection)

    monkeypatch.setattr(Store, "__init__", track_connection)
    yield
    for connection in reversed(connections):
        connection.close()
