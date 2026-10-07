"""Check mínimo: proxy bloqueia IP/usuário ANTES de encaminhar ao upstream."""

from access_defense import proxy


def test_blocked_ip_returns_403_without_forwarding(monkeypatch):
    sent = []
    monkeypatch.setattr(proxy, "is_ip_blocked", lambda ip: (True, "sqli"))
    monkeypatch.setattr(proxy, "is_user_locked", lambda u: (False, None))
    monkeypatch.setattr(proxy, "_log", lambda *a, **k: None)
    # Se encaminhar, isto dispara e falha o teste.
    monkeypatch.setattr(proxy.requests, "request", lambda *a, **k: sent.append(1))

    resp = proxy.app.test_client().get("/rest/products/search?q=x")
    assert resp.status_code == 403
    assert not sent, "não deve encaminhar quando IP bloqueado"


def test_locked_user_returns_403(monkeypatch):
    sent = []
    monkeypatch.setattr(proxy, "is_ip_blocked", lambda ip: (False, None))
    monkeypatch.setattr(proxy, "is_user_locked", lambda u: (True, "brute_force"))
    monkeypatch.setattr(proxy, "_log", lambda *a, **k: None)
    monkeypatch.setattr(proxy.requests, "request", lambda *a, **k: sent.append(1))

    resp = proxy.app.test_client().post("/rest/user/login", json={"username": "admin"})
    assert resp.status_code == 403
    assert not sent


if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-q"]))
