from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import demistomock as demisto

import cryptography.x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256

from typing import Optional


''' STANDALONE FUNCTION '''


def value_from_pem(pem: str) -> Optional[str]:
    try:
        certificate = cryptography.x509.load_pem_x509_certificate(
            pem.encode('ascii'),
            default_backend()
        )

        return certificate.fingerprint(SHA256()).hex()

    except Exception as e:
        demisto.debug(f'Exception in decoding PEM: {e!r}')
        return None


''' MAIN FUNCTION '''


def main():
    pems = argToList(demisto.args().get('input'))

    entries_list = []

    try:
        for pem in pems:
            if (value := value_from_pem(pem)) is not None:
                entries_list.append(value)

        return_results(entries_list)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CertificateValueFromPEM. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
