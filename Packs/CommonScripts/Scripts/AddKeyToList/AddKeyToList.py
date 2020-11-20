"""AddKeyToList
Adds/Updates a Key to a JSON-backed List
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


def add_key_to_list(list_name: str, key_name: str, value: str, append: bool = False, allow_dups: bool = False) -> str:
    res = demisto.executeCommand('getList', {'listName': list_name})
    if (
        not isinstance(res, list)
        or 'Contents' not in res[0]
        or not isinstance(res[0]['Contents'], str)
        or res[0]['Contents'] == 'Item not found (8)'
    ):
        raise ValueError(f'Cannot retrieve list {list_name}')

    list_data: Dict = {}
    if len(res[0]['Contents']) > 0:
        try:
            list_data = json.loads(res[0]['Contents'])
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'List does not contain valid JSON data: {e}')

    if append and key_name in list_data:
        if isinstance(list_data[key_name], list):
            if not allow_dups and value in list_data[key_name]:
                return f'Value already present in key {key_name} of list {list_name}: not appending.'
            list_data[key_name].append(value)
        else:
            old_value = list_data[key_name]
            list_data[key_name] = [old_value, value]
    else:
        list_data[key_name] = value

    demisto.executeCommand('setList', {'listName': list_name, 'listData': json.dumps(list_data)})
    return f'Successfully updated list {list_name}.'


''' COMMAND FUNCTION '''


def add_key_to_list_command(args: Dict[str, Any]) -> CommandResults:

    list_name = args.get('listName', None)
    if not list_name:
        raise ValueError('listName must be specified')

    key_name = args.get('keyName', None)
    if not key_name:
        raise ValueError('keyName must be specified')

    value = args.get('value', None)
    if not value:
        raise ValueError('value must be specified')

    append = argToBoolean(args.get('append'))

    allow_dups = argToBoolean(args.get('allowDups'))

    # Call the standalone function and get the raw response
    result = add_key_to_list(list_name, key_name, value, append, allow_dups)

    return CommandResults(
        readable_output=result
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(add_key_to_list_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute AddKeyToList. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
