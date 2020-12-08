import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import


import urllib.parse
import re
from contextlib import contextmanager
from M2Crypto import SSL, m2
from typing import Dict, Any, Optional, Tuple, Iterator, List


SCHEME_TO_DEFAULT_PORT = {
    'https': 443,
    'http': 80,
    'ftp': 21
}


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
    return [p.rsplit('_',1)[0] for p in dir(m2) if p.endswith('_method')]


def get_hostname_and_port(address: str) -> Tuple[str, int]:
    normalized_address = address
    if re.match(r'^[a-z][A-Z]://.*', address) is None:
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


def get_certificates(hostname: str, port: int, sni: Optional[str], protocol: str, full_chain: bool) -> Optional[List[str]]:
    with SSLContext(protocol=protocol) as ctx:
        ctx.set_verify(SSL.verify_none, 0)  # no lib verification of server cert
        with SSLConnection(ctx) as ssl_connection:
            if sni is not None:
                ssl_connection.set_tlsext_host_name(sni)

            ssl_connection.connect((hostname, port))

            peer_certificate = ssl_connection.get_peer_cert()
            if peer_certificate is None:
                return None

            result: Set[str] = set([peer_certificate.as_pem().decode('ascii')])

            if full_chain:
                peer_certificates = ssl_connection.get_peer_cert_chain()
                if peer_certificates is not None:
                    result.update([c.as_pem().decode('ascii') for c in peer_certificates])

            return sorted(list(result))


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

    arg_protocols = argToList('protocols', 'tls,sslv23')
    protocols = []
    for ap in arg_protocols:
        pkey = ap.lower()
        if not hasattr(m2, f'{pkey}_method'):
            raise ValueError(f'Unknown SSL protocol: {ap}. Known protocols: {get_known_protocols()}')
        protocols.append(pkey)
    if len(protocols) == 0:
        raise ValueError('No protocols specified.')

    full_chain = argToBoolean(args.get('full_chain', 'true'))

    for proto in protocols:
        certificates = get_certificates(hostname, port, sni, proto, full_chain)
        if certificates is not None:
            break
    else:
        raise ValueError('Error retrieving the certificate.')

    return CommandResults(
        readable_output='\n'.join(certificates)
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
