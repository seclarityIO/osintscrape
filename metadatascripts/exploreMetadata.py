"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import argparse
import sys

import authentication
import modify_metadata
import retrieve_metadata


def main():
    """
    """

    # handle arguments
    parser = argparse.ArgumentParser()
    authGroup = parser.add_argument_group("authenticationData",
                                          "arguments available for providing authentication information")
    authGroup.add_argument("-u", "--username", help="a valid username", type=str)
    itemGroup = parser.add_argument_group("itemInformation",
                                          "arguments available for providing information about an item to interact with")
    itemGroup.add_argument("-i", "--item", help="the item you wish to interact with", type=str)
    itemGroup.add_argument("--type", help="a type supported by NetworkSage (destination, behavior, or event supported)",
                           type=str)
    itemGroup.add_argument("--modify", help="modification mode has been chosen for this item", action="store_true")
    itemGroup.add_argument("--view", help="view mode has been chosen for this item", action="store_true")
    itemGroup.add_argument("-j", "--jsonfile", help="location of json file containing items to add to the system",
                           type=str)

    args = parser.parse_args()

    metadata = ""
    """ First, do some initial error handing to get people out of here ASAP if wrong """
    if args.item != "destination":
        print("Only Destination is currently supported.")
        sys.exit()
    if args.view:
        if not args.username:
            args.username = input("username for account:")
        api_key = authentication.get_api_key_for_account(args.username)
        metadata = retrieve_metadata.get_metadata_for_item(args.type, args.item, api_key)
        print("Result:", metadata)
    elif args.modify:
        if not args.jsonfile:
            print("No JSON file provided. Aborting.")
            sys.exit(1)
        modify_metadata.add_metadata_for_item(args.type, args.jsonfile)
    # print("Metadata:", metadata)


if __name__ == "__main__":
    main()
