import json
import dateparser
import time
import socket
import threading

from typing import Any
import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

bind_ip = '0.0.0.0'

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

def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res

def get_params_port(params: dict = demisto.params()) -> int:
    """
    Gets port from the integration parameters
    """
    port_mapping: str = params.get('longRunningPort', '')
    err_msg: str
    port: int
    if port_mapping:
        err_msg = f'Listen Port must be an integer. {port_mapping} is not valid.'
        if ':' in port_mapping:
            port = try_parse_integer(port_mapping.split(':')[1], err_msg)
        else:
            port = try_parse_integer(port_mapping, err_msg)
    else:
        raise ValueError('Please provide a Listen Port.')
    return port

def handle_client_connection(client_socket):
    client_socket.send(b'Welcome\n')
    request = client_socket.recv(1024)
    demisto.debug(f'Long Running: Received {request}')
    client_socket.send(b'ACK!\n')
    ctx = demisto.getIntegrationContext()
    cnt = ctx.get('cnt', 0)
    demisto.debug(f'ctx: {json.dumps(ctx)}')
    demisto.debug(f'cnt: {cnt}')  
    new_cnt = cnt+1
    demisto.setIntegrationContext({'cnt': new_cnt, 'msg': str(request)})
    client_socket.close()

def long_running_loop():
    try:
        bind_port = get_params_port()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((bind_ip, bind_port))
        server.listen(5)  # max backlog of connections
        demisto.debug(f'Long Running: Listening on {bind_ip}:{bind_port}')
        while True:
            client_socket, address = server.accept()
            demisto.debug(f'Long Running: Accepted connection from {address[0]}:{address[1]}')
            client_handler = threading.Thread(
                target=handle_client_connection,
                args=(client_socket,)
            )
            client_handler.start()
            demisto.updateModuleHealth(f'Context: {json.dumps(demisto.getIntegrationContext())}')
    except Exception as e:
        demisto.error(f'Long Running error: {str(e)}')

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

    demisto.debug(f'Command being called is {demisto.command()}')
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
