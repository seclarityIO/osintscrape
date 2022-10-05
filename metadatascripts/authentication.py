"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import os


def get_api_key_for_account(account_name):
    name = account_name[:account_name.find("@")] + "_networksage"
    api_key = os.environ.get(name + "_API_KEY")
    if api_key is None:
        print(
            "Error: No API key available for account. Please enter 'export \'" + name + "_API_KEY\'=\'<your_api_key>' to make this work.")
        return None
    return api_key
