import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import


import urllib.parse
import re
from contextlib import contextmanager
from collections import namedtuple
from M2Crypto import SSL, m2, X509
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


SSLCertificate = TypedDict('SSLCertificate', {
    'sha256': str,
    'md5': str,
    'pem': str,
    'subject': str
})


''' STANDALONE FUNCTION '''


@contextmanager
def SSLContext(protocol: str) -> Iterator[SSL.Context]:
    context = SSL.Context(protocol=protocol, weak_crypto=True)  # we also enable weak crypto. No info is xfered.
    try:
        yield context
    finally:
        context.close()


@contextmanager
def SSLConnection(ctx: SSL.Context) -> Iterator[SSL.Connection]:
    connection = SSL.Connection(ctx)
    try:
        yield connection
    finally:
        connection.close(freeBio=True)


def get_known_protocols():
    return [p.rsplit('_', 1)[0] for p in dir(m2) if p.endswith('_method')]


def get_hostname_and_port(address: str) -> Tuple[str, int]:
    normalized_address = address
    if re.match(r'^[a-zA-Z]+:\/\/.*', address) is None:
        normalized_address = 'fake://' + address
    parsed_url = urllib.parse.urlparse(normalized_address)
    demisto.debug(f'parsed: {parsed_url!r}')

    if (hostname := parsed_url.hostname) is None:
        raise ValueError('Invalid address format.')

    if (port := parsed_url.port) is None:
        if parsed_url.scheme is None or parsed_url.scheme == 'fake':
            raise ValueError('Invalid address format. Port not specified.')

        if parsed_url.scheme not in SCHEME_TO_DEFAULT_PORT:
            raise ValueError(f'Invalid address format. Port not specified and default port for {parsed_url.scheme} is unknown')

        port = SCHEME_TO_DEFAULT_PORT[parsed_url.scheme]

    return hostname, port


def to_ssl_certificate(certificate: X509.X509) -> SSLCertificate:
    return {
        'sha256': certificate.get_fingerprint(md='sha256'),
        'md5': certificate.get_fingerprint(md='md5'),
        'pem': certificate.as_pem().decode('ascii'),
        'subject': certificate.get_subject().as_text()
    }


def get_certificates(hostname: str, port: int, sni: Optional[str],
                     protocol: str, full_chain: bool) -> Optional[List[SSLCertificate]]:
    with SSLContext(protocol=protocol) as ctx:
        ctx.set_verify(SSL.verify_none, 0)  # no lib verification of server cert
        with SSLConnection(ctx) as ssl_connection:
            if sni is not None:
                ssl_connection.set_tlsext_host_name(sni)

            ssl_connection.connect((hostname, port))

            peer_certificate = ssl_connection.get_peer_cert()
            if peer_certificate is None:
                return None

            ssl_certificate = to_ssl_certificate(peer_certificate)
            result: Dict[str, SSLCertificate] = {ssl_certificate['sha256']: ssl_certificate}

            if full_chain:
                peer_certificates = ssl_connection.get_peer_cert_chain()
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

    arg_protocols = argToList(args.get('protocols', 'tlsv1,sslv23'))
    protocols = []
    for ap in arg_protocols:
        pkey = ap.lower()
        if not hasattr(m2, f'{pkey}_method'):
            raise ValueError(f'Unknown SSL protocol: {ap}. Known protocols: {get_known_protocols()}')
        protocols.append(pkey)
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
    readable_ouput = tableToMarkdown('Certificates', certificates, headers=['subject', 'sha256'])

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
