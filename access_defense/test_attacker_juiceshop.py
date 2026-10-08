"""Check mínimo do modo juice-shop: monta os requests certos (caminho, campos
e detecção de sucesso) SEM precisar do Juice Shop no ar — igual test_proxy.py,
usamos monkeypatch pra interceptar o HTTP.
"""

from access_defense import attacker


def _fake_transport():
    """Captura cada request e devolve respostas no formato real do Juice Shop."""
    calls = []

    def fake_post(target, path, payload, timeout=5.0):
        calls.append(("POST", path, payload))
        # Login do Juice Shop: sucesso devolve authentication.token
        return {"status": 200, "body": {"authentication": {"token": "pwned"}}}

    def fake_get(target, path, params, timeout=5.0):
        calls.append(("GET", path, params))
        # Busca do Juice Shop: sucesso devolve lista em 'data'
        return {"status": 200, "body": {"status": "success", "data": [{"id": 1}]}}

    return calls, fake_post, fake_get


def test_juiceshop_hits_native_endpoints_and_fields(monkeypatch):
    calls, fake_post, fake_get = _fake_transport()
    monkeypatch.setattr(attacker, "_post", fake_post)
    monkeypatch.setattr(attacker, "_get", fake_get)

    report = attacker.attack_juiceshop("http://localhost:9000")

    paths = {path for _m, path, _p in calls}
    assert attacker.JUICESHOP_LOGIN in paths
    assert attacker.JUICESHOP_SEARCH in paths

    # Login tem que usar 'email' (não 'username') — é o campo do Juice Shop.
    login_bodies = [p for m, path, p in calls if path == attacker.JUICESHOP_LOGIN]
    assert login_bodies and all("email" in b for b in login_bodies)

    # Busca injeta pelo 'q'.
    search_params = [p for m, path, p in calls if path == attacker.JUICESHOP_SEARCH]
    assert search_params and all("q" in p for p in search_params)


def test_juiceshop_counts_breaches_and_block(monkeypatch):
    calls, fake_post, fake_get = _fake_transport()
    monkeypatch.setattr(attacker, "_post", fake_post)
    monkeypatch.setattr(attacker, "_get", fake_get)

    report = attacker.attack_juiceshop("http://localhost:9000")
    # Todas as respostas simuladas são "sucesso" → toda request vira breach.
    assert report.requests_sent == report.successful_breaches
    assert report.requests_sent == len(calls)

    # Quando o proxy devolve 403, conta como bloqueado (não como breach).
    monkeypatch.setattr(
        attacker, "_post",
        lambda *a, **k: {"_blocked": True, "status": 403, "body": {"error": "ip blocked"}},
    )
    monkeypatch.setattr(
        attacker, "_get",
        lambda *a, **k: {"_blocked": True, "status": 403, "body": {"error": "ip blocked"}},
    )
    blocked_report = attacker.attack_juiceshop("http://localhost:9000")
    assert blocked_report.blocked_by_defense == blocked_report.requests_sent
    assert blocked_report.successful_breaches == 0
