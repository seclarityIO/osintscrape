"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import argparse
import collections
import datetime
import sys
import threading
import time

import requests

import constants
import evidence_collector
import scrape
import utilities
from interactivity import slack, cli
from metadatascripts import modify_metadata, authentication
from testing import testing

# return_data_queue = queue.Queue() # global queue to keep track of data to analyze
return_data_dict = dict()  # global dict to keep track of data to analyze


def prep_buffer(input_sources):
    for val in input_sources:
        return_data_dict[val] = collections.deque()


def main():
    parser = argparse.ArgumentParser()

    inputGroup = parser.add_argument_group("inputData", "arguments available for providing information about the input")
    inputGroup.add_argument("-i", "--inputfile", help="a valid link to a public NetworkSage file", type=str)
    inputGroup.add_argument("--uuid", help="a valid UUID for a NetworkSage file", type=str)
    inputGroup.add_argument("--fresh", help="request a fresh lookup", action="store_true")
    inputGroup.add_argument("-d", "--destination", help="a destination to be analyzed", type=str)
    inputGroup.add_argument("--local",
                            help="should this leverage local calls (for testing new functionality) or use the API endpoints",
                            action="store_true")
    inputGroup.add_argument("--username", help="the username associated with your API key", type=str)
    inputGroup.add_argument("--runtests", help="run test harness to look for changes to known results",
                            action="store_true")
    interaction_layer = parser.add_argument_group("interaction info",
                                                  "arguments about which kind of platform will be used to interact with this script")
    interaction_layer.add_argument("--slack", help="use slack to interact with this script", action="store_true")
    # inputGroup.add_argument("--topic", help="topic to look up", type=str)
    # inputGroup.add_argument("--source", help="source to look up", type=str)

    args = parser.parse_args()
    user_apikey = None

    if args.runtests:
        if args.local:
            testing.test_harness(local=True)
        else:
            testing.test_harness()
        return
    if args.destination:
        if args.uuid:
            print("Destination doesn't take an input file. Quitting.")
            sys.exit(1)
        testing.test_destination_analysis(args.destination, via_slack=args.slack)
        return  # this is a one-and-done piece of functionality
    if not args.fresh:
        if args.uuid:
            if not args.username and len(args.uuid) == 32:
                print("Need to specify username who owns the sample you want to test!")
                return
            elif args.username and len(args.uuid) == 32:
                user_apikey = authentication.get_api_key_for_account(args.username)
                if user_apikey is None:
                    print("Couldn't get API key for specified user, so we can't continue.")
                    return
            if args.local:
                testing.test_samplesummary_categorization_by_uuid(args, user_apikey=user_apikey, local=True)
            else:
                testing.test_samplesummary_categorization_by_uuid(args, user_apikey=user_apikey)
        else:
            testing.do_full_test(args)  # just for testing
        return  # we don't want to follow the stuff below
    else:
        automatedSage_api_key = authentication.get_api_key_for_account(constants.AUTOMATED_SAGE_EMAIL)
        manualSage_api_key = authentication.get_api_key_for_account(constants.MANUAL_SAGE_EMAIL)

    input_sources = ["twitter"]

    prep_buffer(
        input_sources)  # set up all analysis input types with empty double-ended queues so that we can easily process the results

    polling_interval = 60  # we should poll once every minute
    start_time = time.time()

    while True:
        now = datetime.datetime.now(datetime.timezone.utc)
        collect_time = (now - datetime.timedelta(hours=0, minutes=1)).isoformat()

        polling_timer = threading.Timer(polling_interval, None)
        twitter_polling_thread = threading.Thread(target=scrape.collect_twitter,
                                                  kwargs={"time": collect_time, "results_data": return_data_dict})

        # Other polling threads (MISP, OpenPhish, etc...) go here as we develop them
        print("Polling OSINT sources for new information starting at time", str(collect_time))
        polling_timer.start()
        twitter_polling_thread.start()

        time.sleep(5)  # give the underlying threads some time to collect data
        for input_source in input_sources:
            try:
                results = return_data_dict[input_source].popleft()  # take the first entry we see
                collected_evidence = None
                for key in results:  # key should be a username or user identifier
                    if key not in results:
                        continue
                    for result in results[key]:
                        evidence = evidence_collector.EvidenceCollector()
                        user_identifier = key
                        success = True
                        if result["confidence"] >= 75:
                            # prepare for modify metadata. Modify metadata handles checking if we already have this entry
                            json_file = modify_metadata.prepare_json_destination_file(input_source, user_identifier,
                                                                                      result,
                                                                                      input_source + "_" + datetime.datetime.now().strftime(
                                                                                          "%Y%m%d-%H%M%S"))
                            # answer=input("Save metadata (Y/N)? ") # future...not yet
                            answer = "N"  # default answer for now to avoid issues.
                            if answer == "Y":
                                print("Sending", result, "to be saved in NetworkSage as a", result["category"],
                                      "indicator from", input_source, "user", user_identifier)
                                modify_metadata.add_metadata_for_item("destination", json_file)
                            # print("We also want to semi-manually analyze", str(result["links"]), "to capture any additionally unknown knowledge. Preparing that now.")
                            for link in result["links"]:
                                if not utilities.validate_real_destination(link):
                                    continue
                                # otherwise we at least have whois, so continue
                                safe_link = link.replace(".", "[.]")
                                msg = "Found a new item from " + input_source + " user " + user_identifier + " (" + safe_link + ")."  # " to submit to automated sandbox."
                                if args.slack:
                                    msg += "\nOriginal tweet content:\n```" + result["tweet"] + "\n```\n"
                                    collected_evidence = slack.send_notice(msg, args, link, result, evidence)
                                    if collected_evidence is None:
                                        success = False
                                else:
                                    cli.interact_via_cli(msg, args, link, result, evidence)
                                    evidence.other_metadata["channel_id"] = None
                                    evidence.other_metadata["msg_id"] = None
                        else:
                            print("Lower-confidence result.")
                            for link in result["links"]:
                                if not utilities.validate_real_destination(link):
                                    success = False
                                    continue
                                # otherwise we at least have whois, so continue
                                if not utilities.destination_is_resolvable(link):
                                    print(link,
                                          "didn't resolve to anything, so that means that it's probably already down. Ignoring for now.")
                                    success = False
                                    continue
                                safe_link = link.replace(".", "[.]")
                                msg = "Found a new LOW-CONFIDENCE item from " + input_source + " user " + key + " (" + safe_link + ") to submit to sandbox."
                                if args.slack:
                                    msg += "\nOriginal tweet content:\n```" + result["tweet"] + "\n```\n"
                                    collected_evidence = slack.send_notice(msg, args, link, result, evidence)
                                    if collected_evidence is None:
                                        success = False
                                else:
                                    cli.interact_via_cli(msg, args, link, result, evidence)
                                    evidence.other_metadata["channel_id"] = None
                                    evidence.other_metadata["msg_id"] = None
                        if not success or collected_evidence is None:
                            print("Something failed. Not performing analysis.")
                            continue
                        else:
                            evidence = collected_evidence
                        if evidence.other_metadata != {}:
                            msg = ""
                            request_headers = {"apikey": ""}
                            requests.post(constants.SAMPLES_API_ENDPOINT
                                          + evidence.sample_metadata["uuid"]
                                          + constants.SUMMARY_API
                                          , headers=request_headers
                                          )
                            summary_data = utilities.get_sample_details(evidence.sample_metadata["uuid"],
                                                                        constants.SUMMARY_API,
                                                                        request_headers
                                                                        )
                            if summary_data is None:
                                msg = "Something went wrong while trying to get summary for sample."
                                slack.send_thread_reply(evidence.other_metadata["channel_id"], msg,
                                                        evidence.other_metadata["msg_id"])
                                continue
                            requests.post(constants.SAMPLES_API_ENDPOINT
                                          + evidence.sample_metadata["uuid"]
                                          + constants.CATEGORIZATION_API
                                          , headers=request_headers
                                          )
                            categorized_activity_data = utilities.get_sample_details(evidence.sample_metadata["uuid"],
                                                                                     constants.CATEGORIZATION_API,
                                                                                     request_headers
                                                                                     )
                            if categorized_activity_data is None:
                                msg = "Something went wrong while trying to get categorization for sample."
                                slack.send_thread_reply(evidence.other_metadata["channel_id"], msg,
                                                        evidence.other_metadata["msg_id"])
                                continue
                            for item in ["verdict", "confidence", "summary", "details"]:
                                msg += "*" + item.capitalize() + ":* " + summary_data[item] + "\n"
                            slack.send_thread_reply(evidence.other_metadata["channel_id"], msg,
                                                    evidence.other_metadata["msg_id"])
                            # analysis.determine_next_steps(verdict, evidence, proposed_actions_dict, categorized_activity_data, client, osint_source="twitter")
            except IndexError:
                print("No results yet for", input_source)
        time.sleep(polling_interval - ((time.time() - start_time) % polling_interval))


main()
