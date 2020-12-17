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


def test_proxy_tunnel(mocker):
    from CertificateFromSSLServer import proxy_tunnel
    from http.client import PROXY_AUTHENTICATION_REQUIRED, OK

    last_http_conn_mock_instance = None

    class HTTPResponseMock:
        def __init__(self, status):
            self.status = status

    class HTTPConnectionMock:
        def __init__(self, host, port):
            nonlocal last_http_conn_mock_instance

            self.sock = "fake-sock"
            self.host = host
            self.port = port
            self.requests = []
            last_http_conn_mock_instance = self

        def request(self, method, arg, headers):
            self.requests.append((
                method, arg, headers
            ))
        
        def getresponse(self):
            if len(self.requests) == 0:
                raise RuntimeError('getresponse before request')

            if self.host == 'auth-proxy' and not 'Proxy-Authorization' in self.requests[-1][2]:
                return HTTPResponseMock(PROXY_AUTHENTICATION_REQUIRED)

            return HTTPResponseMock(OK)

    mocker.patch('CertificateFromSSLServer.http.client.HTTPConnection', side_effect=HTTPConnectionMock)

    result = proxy_tunnel(['no-auth-proxy', 8443, None, None], 'demisto.pan.dev', 443)
    assert result == 'fake-sock'
    assert last_http_conn_mock_instance != None
    assert last_http_conn_mock_instance.host == 'no-auth-proxy'
    assert last_http_conn_mock_instance.port == 8443
    assert len(last_http_conn_mock_instance.requests) == 1
    assert last_http_conn_mock_instance.requests[0] == ('CONNECT', 'demisto.pan.dev:443', {"Host": "demisto.pan.dev:443"})

    last_http_conn_mock_instance = None

    result = proxy_tunnel(['auth-proxy', 8443, None, None], 'demisto.pan.dev', 443)
    assert result == 'fake-sock'
    assert last_http_conn_mock_instance != None
    assert last_http_conn_mock_instance.host == 'no-auth-proxy'
    assert last_http_conn_mock_instance.port == 8443
    assert len(last_http_conn_mock_instance.requests) == 1
