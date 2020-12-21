import pytest


def load_json(path):
    import json

    with open(path, 'r') as f:
        return json.load(f)


def load_pem(path):
    import OpenSSL.crypto

    with open(path, 'rb') as f:
        cert_bytes = f.read()

    return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)


def load_file(path):
    with open(path, 'rb') as f:
        cert_bytes = f.read()

    return cert_bytes.decode('ascii')


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
    from base64 import b64encode

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

            if self.host == 'auth-proxy' and 'Proxy-Authorization' not in self.requests[-1][2]:
                return HTTPResponseMock(PROXY_AUTHENTICATION_REQUIRED)

            return HTTPResponseMock(OK)

    mocker.patch('CertificateFromSSLServer.http.client.HTTPConnection', side_effect=HTTPConnectionMock)

    result = proxy_tunnel(['no-auth-proxy', 8443, None, None], 'demisto.pan.dev', 443)
    assert result == 'fake-sock'
    assert last_http_conn_mock_instance is not None
    assert last_http_conn_mock_instance.host == 'no-auth-proxy'
    assert last_http_conn_mock_instance.port == 8443
    assert len(last_http_conn_mock_instance.requests) == 1
    assert last_http_conn_mock_instance.requests[0] == ('CONNECT', 'demisto.pan.dev:443', {"Host": "demisto.pan.dev:443"})

    last_http_conn_mock_instance = None

    with pytest.raises(RuntimeError):
        result = proxy_tunnel(['auth-proxy', 8443, None, None], 'demisto.pan.dev', 443)

    result = proxy_tunnel(['auth-proxy', 8443, "u", "p"], 'demisto.pan.dev', 443)
    assert result == 'fake-sock'
    assert last_http_conn_mock_instance is not None
    assert last_http_conn_mock_instance.host == 'auth-proxy'
    assert last_http_conn_mock_instance.port == 8443
    assert len(last_http_conn_mock_instance.requests) == 2
    assert last_http_conn_mock_instance.requests[0] == ('CONNECT', 'demisto.pan.dev:443', {"Host": "demisto.pan.dev:443"})
    assert last_http_conn_mock_instance.requests[1] == ('CONNECT', 'demisto.pan.dev:443', {
        "Host": "demisto.pan.dev:443",
        'Proxy-Authorization': f'basic {b64encode("u:p".encode("utf-8")).decode("ascii")}'
    })


def test_get_certificates(mocker):
    from CertificateFromSSLServer import get_certificates
    import OpenSSL.SSL

    class SSLConnectionMock:
        def __init__(self, context, socket):
            self.context = context
            self.socket = socket
            self.connect_state = False
            self.tlsext_host_name = None
            self.handshaked = False
            self.closed = False
            self.shut_down = False

        def set_connect_state(self):
            self.connect_state = True

        def set_tlsext_host_name(self, name):
            self.tlsext_host_name = name

        def do_handshake(self):
            self.handshaked = True

        def get_peer_certificate(self):
            if self.tlsext_host_name == b'www.example.com':
                return load_pem('test_data/Server.pem')

            return load_pem('test_data/DefaultServer.pem')

        def get_peer_cert_chain(self):
            if self.tlsext_host_name == b'www.example.com':
                return [
                    load_pem('test_data/Server.pem'),
                    load_pem('test_data/CA.pem')
                ]

            return load_pem('test_data/DefaultServer.pem')

        def close(self):
            self.closed = True

        def shutdown(self):
            self.shut_down = True

    mocker.patch('CertificateFromSSLServer.OpenSSL.SSL.Context')
    mocker.patch('CertificateFromSSLServer.socket.socket')
    mocker.patch('CertificateFromSSLServer.OpenSSL.SSL.Connection', side_effect=SSLConnectionMock)

    result = get_certificates('www.example.com', 443, None, OpenSSL.SSL.SSLv23_METHOD, False, proxy=None)
    assert result == [{
        'sha256': 'fb51ff194b5f221966500ae50e81d53fd3d3ad982a434dfe3996ab679d117d34',
        'md5': '6c013555f16cab183959bee1959a2d97',
        'subject': 'C=IT, ST=RE, L=Codemondo, CN=SSLServer2',
        'issuer': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerCA',
        'pem': load_file('test_data/DefaultServer.pem')
    }]

    result = get_certificates('www.example.com', 443, 'www.example.com', OpenSSL.SSL.SSLv23_METHOD, True, proxy=None)
    assert result == [{
        'sha256': '24b6f49c9cb1bd43fd00d57d095f05131d7d526489c975dc3b669fd13075fa7a',
        'md5': 'd25e06796008e53299e7305381d908ba',
        'subject': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerCA',
        'issuer': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerCA',
        'pem': load_file('test_data/CA.pem')
    }, {
        'sha256': 'f8aed12955c059d11afcbcfa2dc8dae85046edd399b66bc5f7343d6d3beadab6',
        'md5': '952d35025caec0b4cd7354eb38051da9',
        'subject': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerServer',
        'issuer': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerCA',
        'pem': load_file('test_data/Server.pem')
    }]


def test_certificate_from_ssl_server_command(mocker):
    from CertificateFromSSLServer import certificate_from_ssl_server_command, PROTOCOL_TO_METHOD

    get_certificates_mock = mocker.patch('CertificateFromSSLServer.get_certificates', return_value=[{
        'sha256': '24b6f49c9cb1bd43fd00d57d095f05131d7d526489c975dc3b669fd13075fa7a',
        'md5': 'd25e06796008e53299e7305381d908ba',
        'subject': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerCA',
        'issuer': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerCA',
        'pem': load_file('test_data/CA.pem')
    }, {
        'sha256': 'f8aed12955c059d11afcbcfa2dc8dae85046edd399b66bc5f7343d6d3beadab6',
        'md5': '952d35025caec0b4cd7354eb38051da9',
        'subject': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerServer',
        'issuer': 'C=IT, ST=RE, L=Codemondo, CN=SSLFromServerCA',
        'pem': load_file('test_data/Server.pem')
    }])

    result = certificate_from_ssl_server_command({
        'address': 'https://www.example.com'
    })

    assert result.to_context() == load_json('test_data/certificate_from_ssl_server_command.json')
    get_certificates_mock.assert_called_once_with(
        'www.example.com',
        443,
        'www.example.com',
        PROTOCOL_TO_METHOD['flex'],
        True,
        None
    )
