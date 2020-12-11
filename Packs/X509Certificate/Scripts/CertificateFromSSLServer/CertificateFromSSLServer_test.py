import pytest


def load_json(path):
    import json

    with open(path, 'r') as f:
        return json.load(f)


def test_get_hostname_and_port():
    from CertificateFromSSLServer import get_hostname_and_port

    test_vector = load_json('test_data/get_hostname_and_port.json')
    for test in test_vector:
        if test[1] is None:
            with pytest.raises(ValueError):
                get_hostname_and_port(test[0])
            continue

        assert test[1] == list(get_hostname_and_port(test[0]))


def test_get_hostname_and_port_http():
    from CertificateFromSSLServer import get_hostname_and_port

    test_vector = load_json('test_data/get_hostname_and_port_http.json')
    for test in test_vector:
        if test[1] is None:
            with pytest.raises(ValueError):
                get_hostname_and_port(test[0], force_http=True)
            continue

        assert test[1] == list(get_hostname_and_port(test[0]))
