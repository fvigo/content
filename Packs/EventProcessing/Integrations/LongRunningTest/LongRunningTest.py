import json
import dateparser
import time

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def say_hello(self, name):
        return f'Hello {name}'


def test_module(client):
    return 'ok'

def update_cnt(client, args):
    new_cnt = int(args.get('cnt'), 0)
    if not new_cnt or new_cnt <= 0:
        raise ValueError('cnt must be a positive integer')

    cnt = demisto.getIntegrationContext().get('cnt', 0)        
    demisto.log(f'cnt was: {cnt}, new cnt is {new_cnt}')
    demisto.setIntegrationContext({'cnt': new_cnt})
    cnt = demisto.getIntegrationContext().get('cnt', 0)
    demisto.log(f'now cnt is: {cnt}')    
    return client.say_hello(str(cnt)), None, None

def long_running_loop():
    while True:
        cnt = demisto.getIntegrationContext().get('cnt', 0)
        demisto.updateModuleHealth(f'hi: {cnt}')
        demisto.setIntegrationContext({'cnt': cnt+1})
        time.sleep(10)

def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    (f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'long-running-execution':
            long_running_loop()

        elif demisto.command() == 'longrunningtest-update_cnt':
            return_outputs(*update_cnt(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
