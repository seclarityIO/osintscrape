"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import json
import os
import sys

import requests


def bearer_oauth(r):  # bearer_token):
    """
    Method required by bearer token authentication.
    """
    # To set your environment variables in your terminal run the following line:
    # export "BEARER_TOKEN"="<your_bearer_token>"
    bearer_token = os.environ.get("BEARER_TOKEN")
    if bearer_token is None:
        print(
            "Error: No bearer token available for Twitter API. Please enter 'export \'BEARER_TOKEN\'=\'<name_of_your_token>' to make this work.")
        sys.exit(1)

    r.headers["Authorization"] = f"Bearer {bearer_token}"
    r.headers["User-Agent"] = "v2RecentSearchPython"
    return r


def connect_to_endpoint(url, params):
    response = requests.get(url, auth=bearer_oauth, params=params)
    # print(response.status_code)
    if response.status_code != 200:
        raise Exception(response.status_code, response.text)
    return response.json()


def setup(search_url, query_params):
    json_response = connect_to_endpoint(search_url, query_params)
    return (json.dumps(json_response, indent=4, sort_keys=True))
