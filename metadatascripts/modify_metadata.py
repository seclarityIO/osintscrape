"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import json
import sys
from pathlib import Path

import requests

import utilities
from metadatascripts import retrieve_metadata, authentication


def prepare_json_destination_file(osint_source, user_identifier, dict_data, name):
    Path("outputs").mkdir(parents=True, exist_ok=True)
    outfile_name = "outputs/" + name + ".json"
    json_output_file = open(outfile_name, "w")
    json_output_file.write("{\n\t'destinations':\n\t\t[")
    # failed_or_skipped_file=open("failed_or_skipped.txt", "w")
    i = 0

    # go from dict_data to the expected fields below
    topic = dict_data["category"]

    for link in dict_data["links"]:
        data = dict()
        destination = utilities.get_destination_from_link(link)
        if len(destination) == 0:
            print("Something went wrong parsing destination. Skipping.")
            continue
        if ":" in destination:
            print("Destination", destination, "already has a port. Using it.")
            data["destinationName"] = destination
        else:  # default to 443 if no port
            data["destinationName"] = destination + ":443"
        data["title"] = "Known " + topic.capitalize() + " Site"
        data[
            "description"] = "This Destination is known to be a " + topic + " site. It was discovered by " + osint_source + " user " + user_identifier + "."
        data["relevance"] = "knownBad"
        data["destinationTags"]: ""
        data["platformHintTags"]: ""
        data["associatedAppOrServiceTags"]: ""
        data["impactsTags"]: ""
        data["activityPurposeTags"]: ""
        data["attackVectorTags"]: ""
        data["threatTags"]: [topic.capitalize()]
        data["securityTags"]: ""
        if i != 0:
            json_output_file.write("\n\t\t,")
        i += 1
        json_output_file.write(json.dumps(data, indent=4))
    json_output_file.write("\n\t]\n}")
    json_output_file.close()
    # print("Prepped results written to", outfile_name)
    return outfile_name


def save_destination_metadata_from_slack(destination_name, metadata_json):
    """Since we already do checks to make sure that we're only updating (instead of overwriting changes) existing
        Destination metadata changes, we can go ahead and save this right away.
    """
    endpoint_url = ("https://api.seclarity.io/sec/v1.0/destinations/"
                    + destination_name
                    )
    print("Metadata to save for", destination_name, "-->", metadata_json)
    api_key = authentication.get_api_key_for_account("modified@seclarity.io")  # TODO: Be smarter here!
    request_headers = {"apikey": api_key,
                       "content-type": "application/json"
                       }
    request = requests.Request("POST", endpoint_url, data=json.dumps(metadata_json), headers=request_headers)
    prepped = request.prepare()
    print("Sending following content to", prepped.url, "-->", prepped.body)
    s = requests.Session()
    result = s.send(prepped)
    print("Result:", result)
    result_json = json.loads(result.text)
    return result_json


def add_metadata_for_item(item_type, modification_file):
    if item_type == "destination":
        endpoint = "destinations"
    else:
        print("Unsupported item type", item_type + ". Aborting.")
        sys.exit(1)
    """
    elif item_type == "behavior":
        endpoint = "behaviors"
    elif item_type == "event":
        endpoint = "events"
    """
    endpoint_url = "https://api.seclarity.io/sec/v1.0/" + endpoint + "/"

    with open(modification_file, "r") as mods:
        json_data = json.load(mods)
    if not json_data:
        print("No data. Aborting.")
        sys.exit(1)
    # print("Collected the following JSON data:", json_data)
    username = input("Enter your username: ")
    api_key = authentication.get_api_key_for_account(username)
    for item in json_data["destinations"]:
        # print("item:", item)
        # print("Would be modifying following item:", endpoint_url+item["destinationName"])
        # print("With following metadata:", item)
        destination = item["destinationName"]
        url = endpoint_url + destination
        data = item
        data.pop("destinationName",
                 None)  # destination metadata doesn't include name, so remove it from JSON dict if it exists
        # check if content already exists:
        metadata = retrieve_metadata.get_metadata_for_item(item_type, destination, api_key)
        if metadata:
            print("WARNING! This item already has content:", metadata)
            input("Press enter if you wish to continue:")
        request_headers = {"apikey": api_key,
                           "content-type": "application/json"
                           }
        request = requests.Request("POST", url, data=json.dumps(data), headers=request_headers)
        prepped = request.prepare()
        print("Ready to send following content to", prepped.url, "-->", prepped.body)
        input("Press enter to save this information:")
        s = requests.Session()
        result = s.send(prepped)
        print("Result:", result)
        resultJson = json.loads(result.text)
        if resultJson["error"]:
            print("Error:", resultJson["body"])
            sys.exit(1)
    # return resultJson["body"]
