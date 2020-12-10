import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import


import urllib.parse
import re
import socket
from collections import namedtuple
import OpenSSL.SSL
import OpenSSL.crypto
from typing import (
    Dict, Any, Optional,
    Tuple, Iterator, List,
    TypedDict
)
from operator import itemgetter


SCHEME_TO_DEFAULT_PORT = {
    'https': 443,
    'http': 80,
    'ftp': 21
}


PROTOCOL_TO_METHOD = {
    'flex': OpenSSL.SSL.SSLv23_METHOD,  # flexible method, any protocol
    'tlsv1': OpenSSL.SSL.TLSv1_METHOD,
    'tlsv1_1': OpenSSL.SSL.TLSv1_1_METHOD,
    'tlsv1_2': OpenSSL.SSL.TLSv1_2_METHOD,
    'sslv2': OpenSSL.SSL.SSLv2_METHOD,  # really ???
    'sslv3': OpenSSL.SSL.SSLv3_METHOD  # really ??
}


SSLCertificate = TypedDict('SSLCertificate', {
    'sha256': str,
    'md5': str,
    'pem': str,
    'subject': str,
    'issuer': str
})


''' STANDALONE FUNCTION '''


def verify_cb(conn, cert, errnum, depth, ok):
    return ok


def get_hostname_and_port(address: str) -> Tuple[str, int]:
    normalized_address = address
    if re.match(r'^[a-zA-Z]+:\/\/.*', address) is None:
        normalized_address = 'fake://' + address
    parsed_url = urllib.parse.urlparse(normalized_address)

    if (hostname := parsed_url.hostname) is None:
        raise ValueError('Invalid address format.')

    if (port := parsed_url.port) is None:
        if parsed_url.scheme is None or parsed_url.scheme == 'fake':
            raise ValueError('Invalid address format. Port not specified.')

        if parsed_url.scheme not in SCHEME_TO_DEFAULT_PORT:
            raise ValueError(f'Invalid address format. Port not specified and default port for {parsed_url.scheme} is unknown')

        port = SCHEME_TO_DEFAULT_PORT[parsed_url.scheme]

    return hostname, port


def to_ssl_certificate(certificate: OpenSSL.crypto.X509) -> SSLCertificate:
    return {
        'sha256': certificate.digest('sha256').hex(),
        'md5': certificate.digest('md5').hex(),
        'pem': OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate).decode('ascii'),
        'subject': ', '.join([f'{name}={value}' for name, value in certificate.get_subject().get_components()]),
        'issuer': ', '.join([f'{name}={value}' for name, value in certificate.get_issuer().get_components()])
    }


def get_certificates(hostname: str, port: int, sni: Optional[str],
                     protocol: Any, full_chain: bool) -> Optional[List[SSLCertificate]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))

    context = OpenSSL.SSL.Context(method=protocol)
    context.set_verify(OpenSSL.SSL.VERIFY_NONE, callback=verify_cb)

    connection = OpenSSL.SSL.Connection(context, socket=sock)
    connection.set_connect_state()
    if sni is not None:
        connection.set_tlsext_host_name(sni.encode('utf-8'))
    connection.do_handshake()

    peer_certificate = connection.get_peer_certificate()
    if peer_certificate is None:
        return None

    ssl_certificate = to_ssl_certificate(peer_certificate)
    result: Dict[str, SSLCertificate] = {ssl_certificate['sha256']: ssl_certificate}

    if full_chain:
        peer_certificates = connection.get_peer_cert_chain()
        if peer_certificates is not None:
            for c in peer_certificates:
                ssl_certificate = to_ssl_certificate(c)
                result[ssl_certificate['sha256']] = ssl_certificate

    return sorted(list(result.values()), key=itemgetter('subject'))


''' COMMAND FUNCTION '''


def certificate_from_ssl_server_command(args: Dict[str, Any]) -> CommandResults:
    address: Optional[str] = args.get('address')
    if address is None:
        raise ValueError('address argument is required.')

    hostname, port = get_hostname_and_port(address)

    arg_sni: str = args.get('sni', 'true')
    sni: Optional[str]
    try:
        sni = hostname if argToBoolean(arg_sni) else None
    except ValueError:
        sni = arg_sni

    arg_protocols = argToList(args.get('protocols', 'flex'))
    protocols = []
    for ap in arg_protocols:
        method = PROTOCOL_TO_METHOD.get(ap.lower())
        if method is None:
            raise ValueError(f'Unknown SSL protocol: {ap}. Known protocols: {", ".join(list(PROTOCOL_TO_METHOD.keys()))}')
        protocols.append(method)
    if len(protocols) == 0:
        raise ValueError('No protocols specified.')

    full_chain = argToBoolean(args.get('full_chain', 'true'))

    certificates: Optional[List[SSLCertificate]]
    for proto in protocols:
        certificates = get_certificates(hostname, port, sni, proto, full_chain)
        if certificates is not None:
            break
    else:
        raise ValueError('Error retrieving the certificate.')

    indicators = [
        Common.Certificate(
            subject_dn=c['subject'],
            issuer_dn=c['issuer'],
            sha256=c['sha256'].lower(),
            md5=c['md5'].lower(),
            pem=c['pem'],
            dbot_score=Common.DBotScore(
                c['sha256'],
                DBotScoreType.CERTIFICATE,
                'X509Certificate',
                Common.DBotScore.NONE
        ))
        for c in certificates
    ]
    readable_ouput = tableToMarkdown('Certificates', certificates, headers=['subject', 'issuer', 'sha256'])

    return CommandResults(
        readable_output=readable_ouput,
        indicators=indicators
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(certificate_from_ssl_server_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CertificateFromSSLServer. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
