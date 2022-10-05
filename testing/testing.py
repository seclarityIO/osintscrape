"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import json
import sys
import time

import requests

import constants
import evidence_collector
import scrape
import utilities
from analysis import analysis
from display import display
from interactivity import slack
from metadatascripts import authentication


def test_harness(local=False):
    """Takes the results of known, categorized samples and determines whether we have matched the expected output, the
        desired output, or something else. Expected output could be wrong in some cases, which is why there is a notes
        section to capture additional information about why the expected and desired outputs diverge. Any time a scoring
        algorithm change occurs, these samples should be tested to see if things are changing positively or negatively.

        If the "local" variable is passed in as True, it means we should be testing local (presumably enhanced)
        functionality to determine whether it should be deployed to our API endpoints.
    """
    test_categories = ["unknown_malicious.json"
        , "known_malicious.json"
        , "new_uninteresting.json"
        , "established_uninteresting.json"
                       ]
    fields_to_compare = ["verdict", "confidence"]
    derived_fields_from_summary = ["attack_type", "targeted_brand"]
    counts_from_categorization = ["Impact", "Malicious Activity", "Suspicious Activity", "Attack Vector"]
    total_tests = 0  # all tests we have
    expected_failures = 0  # count those where we currently know we have an issue to resolve
    unexpected_failures = 0  # count those where we have a new issue to resolve
    now = str(time.time())
    if not local:
        filename = now + "_results.txt"
    else:
        filename = now + "_LOCAL_results.txt"
    with open("testing/results/" + filename, "w") as outfile:
        for cat in test_categories:
            outfile.write("=============================================\nTesting cases from " + cat + "\n")
            with open("testing/categories/" + cat) as filedata:
                test_cases = json.load(filedata)
            outfile.write("Testing " + str(len(test_cases["samples"])) + " test cases" + "\n")
            for case in test_cases["samples"]:
                total_tests += 8  # there are 8 total tests for each test case
                outfile.write("Getting data for sample " + case["sample_id"] + "\n")
                if len(case["sample_id"]) == 0:
                    outfile.write("No sample ID, so nothing to do.\n")
                    continue
                if "owner" not in case.keys():
                    outfile.write("Missing owner information, so we can't analyze this sample.\n")
                    continue
                else:
                    user_apikey = authentication.get_api_key_for_account(case["owner"])
                    request_headers = {"apikey": user_apikey}
                if not local:
                    endpoint = constants.SAMPLES_API_ENDPOINT + case["sample_id"]
                    requests.post(constants.SAMPLES_API_ENDPOINT
                                  + case["sample_id"]
                                  + constants.SUMMARY_API
                                  , headers=request_headers
                                  )
                    summary_data = utilities.get_sample_details(case["sample_id"],
                                                                constants.SUMMARY_API,
                                                                request_headers
                                                                )
                    if summary_data is None:
                        msg = "Something went wrong while trying to get summary for sample."
                        outfile.write(msg + " Skipping.\n")
                        continue
                else:
                    evidence = evidence_collector.EvidenceCollector(case["sample_id"])
                    summary_data = display.get_sample_summary(case["sample_id"]
                                                              , incoming_evidence=evidence
                                                              , apikey=user_apikey
                                                              )
                if not local:
                    requests.post(constants.SAMPLES_API_ENDPOINT
                                  + case["sample_id"]
                                  + constants.CATEGORIZATION_API
                                  , headers=request_headers
                                  )
                    categorization_data = utilities.get_sample_details(case["sample_id"],
                                                                       constants.CATEGORIZATION_API,
                                                                       request_headers
                                                                       )
                    if categorization_data is None:
                        msg = "Something went wrong while trying to get categorization for sample."
                        outfile.write(msg + " Skipping.\n")
                        continue
                else:
                    categorization_data = display.get_categorized_activity_groups(case["sample_id"]
                                                                                  , incoming_evidence=evidence
                                                                                  , apikey=user_apikey
                                                                                  )  # this will be an API call
                for field in fields_to_compare:
                    qualifier = ""
                    if case["desired_output"][field] == summary_data[field]:
                        prefix = "\t| SUCCESS |\t\t"
                        outfile.write(prefix + field + " (" + summary_data[field] + ") matches DESIRED output!\n")
                    elif case["expected_output"][field] == summary_data[field]:
                        if field not in case["expected_output"]["unacceptable_fields"]:
                            prefix = "\t| (Partial) SUCCESS |\t"
                        else:
                            prefix = "\t| FAIL |\t\t"
                            expected_failures += 1
                            qualifier = "(which is not what we want)"
                        outfile.write(prefix + field + " (" + summary_data[
                            field] + ") matches expected output " + qualifier + "\n")
                    else:
                        prefix = "\t| FAIL |\t\t"
                        outfile.write(
                            prefix + field + " (" + summary_data[field] + ") doesn't match NEITHER expected (" +
                            case["expected_output"][field] + ") nor desired (" + case["desired_output"][
                                field] + ") output!\n")
                        unexpected_failures += 1
                for field in derived_fields_from_summary:
                    qualifier = ""
                    if case["desired_output"][field].lower() in summary_data["summary"].lower():
                        prefix = "\t| SUCCESS |\t\t"
                        outfile.write(
                            prefix + field + " matches DESIRED output (" + case["desired_output"][field] + ")\n")
                    elif case["expected_output"][field].lower() in summary_data["summary"].lower():
                        if field not in case["expected_output"]["unacceptable_fields"]:
                            prefix = "\t| (Partial) SUCCESS |\t"
                        else:
                            prefix = "\t| FAIL |\t\t"
                            expected_failures += 1
                            qualifier = "(which is not what we want)"
                        outfile.write(prefix + field + " matches expected output (" + case["expected_output"][
                            field] + ") " + qualifier + "\n")
                    else:
                        prefix = "\t| FAIL |\t\t"
                        outfile.write(
                            prefix + "NEITHER expected (" + case["expected_output"][field] + ") nor desired (" +
                            case["desired_output"][field] + ") output matches discovered " + field + "!\n")
                        unexpected_failures += 1
                for field_count in counts_from_categorization:
                    qualifier = ""
                    if len(case["desired_output"][field_count]) == len(categorization_data[field_count]):
                        prefix = "\t| SUCCESS |\t\t"
                        outfile.write(prefix + field_count + " count (" + str(
                            len(categorization_data[field_count])) + ") matches DESIRED output!\n")
                    elif len(case["expected_output"][field_count]) == len(categorization_data[field_count]):
                        if field_count not in case["expected_output"]["unacceptable_fields"]:
                            prefix = "\t| (Partial) SUCCESS |\t"
                        else:
                            prefix = "\t| FAIL |\t\t"
                            expected_failures += 1
                            qualifier = "(which is not what we want)"
                        outfile.write(prefix + field_count + " count (" + str(
                            len(categorization_data[field_count])) + ") matches expected output " + qualifier + "\n")
                    else:
                        prefix = "\t| FAIL |\t\t"
                        outfile.write(prefix + field_count + " count (" + str(
                            len(categorization_data[field_count])) + ") doesn't match NEITHER expected (" + str(
                            len(case["expected_output"][field_count])) + ") nor desired (" + str(
                            len(case["desired_output"][field_count])) + ") output!\n")
                        unexpected_failures += 1
                try:
                    outfile.write("Notes on result: " + str(case["notes"]) + "\n")
                except:
                    pass  # no notes
        outfile.write("=============================================\nFinal results:\n")
        outfile.write("Out of " + str(total_tests) + " total tests, we had:\n")
        outfile.write("Expected failures: " + str(expected_failures) + "\n")
        outfile.write("UNEXPECTED failures: " + str(unexpected_failures) + "\n")
        print("Test complete. Results stored at testing/results/" + now + "_results.txt")


def demo(sampleId, via_slack):
    """Function for our demo case to run through so we don't cause issues with other logic right now.
    """
    evidence = evidence_collector.EvidenceCollector(sampleId)
    if via_slack:
        should_quit = False
        if "uuid" not in evidence.sample_metadata.keys():
            msg = "Invalid UUID found. Cannot perform analysis."
            should_quit = True
        else:
            msg = "Analyzing sample with UUID "
        link = utilities.generate_sample_link_from_uuid(evidence.sample_metadata["uuid"])
        if link is None:
            msg = "Invalid UUID found. Cannot perform analysis."
            should_quit = True
        else:
            msg += ("<"
                    + link
                    + "|"
                    + evidence.sample_metadata["uuid"]
                    + ">"
                    )  # add link to sample as link with text of UUID
        sent = slack.send_new_message(channel="#some_channel", message_text=msg)
        evidence.other_metadata["channel_id"] = sent["channel"]
        evidence.other_metadata["msg_id"] = sent["ts"]
        if should_quit:
            return None
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
        slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
        return None
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
        msg = "Something went wrong while trying to get summary for sample."
        slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
        return None
    with open("summary.json", "w") as out:
        out.write(json.dumps(summary_data
                             , indent=4
                             )
                  )
    with open("categorized.json", "w") as out:
        out.write(json.dumps(categorized_activity_data
                             , indent=4
                             )
                  )
    for item in ["verdict", "confidence", "summary", "details"]:  # summary_data.keys():
        msg += "*" + item.capitalize() + ":* " + summary_data[item] + "\n"
    slack.send_thread_reply(evidence.other_metadata["channel_id"]
                            , msg, evidence.other_metadata["msg_id"]
                            )
    # analysis.determine_next_steps(verdict
    #                            , evidence
    #                            , proposed_actions_dict
    #                            , categorized_activity_data
    #                            , client
    #                            )
    print(
        " ====================================================\n| Finished analyzing NetworkSage sample. |\n ====================================================")
    return None


def test_samplesummary_categorization_by_uuid(args, user_apikey, local=False):
    """In this case we only have a NetworkSage file (not any sandbox or twitter info), so we need to figure it all out
        just with that data. This is the function that represents what we should expose to users.
    """
    via_slack = args.slack
    evidence = evidence_collector.EvidenceCollector(args.uuid)
    is_public = False
    if "uuid" not in evidence.sample_metadata.keys():
        print("No sample UUID specified. Quitting.")
        sys.exit(1)
    msg = "`TEST (not new, please disregard!)`\n"
    if via_slack:
        link = utilities.generate_sample_link_from_uuid(evidence.sample_metadata["uuid"])
        if link is None:
            msg += ("Something failed while trying to generate link for sample with UUID `"
                    + evidence.sample_metadata["uuid"]
                    + "`. Reanalyzing anyway."
                    )
        else:
            msg += ("Reanalyzing sample with UUID <"
                    + link
                    + "|"
                    + evidence.sample_metadata["uuid"]
                    + ">"
                    )
        sent = slack.send_new_message(channel="#some_channel", message_text=msg)
        evidence.other_metadata["channel_id"] = sent["channel"]
        evidence.other_metadata["msg_id"] = sent["ts"]
    msg = ""

    if not local:
        request_headers = {"apikey": user_apikey}
        res = requests.post(constants.SAMPLES_API_ENDPOINT
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
            if via_slack:
                slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
            else:
                print(msg)
            return None
    else:  # we're testing the local functionality here
        summary_data = display.get_sample_summary(evidence.sample_metadata["uuid"]
                                                  , incoming_evidence=evidence
                                                  , apikey=user_apikey
                                                  , via_slack=via_slack
                                                  )  # this will be an API call
    if not local:
        res = requests.post(constants.SAMPLES_API_ENDPOINT
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
            if via_slack:
                slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
            else:
                print(msg)
            return None
    else:
        categorized_activity_data = display.get_categorized_activity_groups(evidence.sample_metadata["uuid"]
                                                                            , incoming_evidence=evidence
                                                                            , apikey=user_apikey
                                                                            )  # this will be an API call
    if summary_data is None or categorized_activity_data is None:
        msg = "Failed to collect data for this sample. This often occurs if the sample is empty or if you do not have access to view it."
    else:
        for item in ["verdict", "confidence", "summary", "details"]:
            msg += "*" + item.capitalize() + ":* " + summary_data[item] + "\n"
    if via_slack:
        slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
    else:
        print(msg)
    if summary_data is not None:
        with open("summary.json", "w") as out:
            out.write(json.dumps(summary_data
                                 , indent=4
                                 )
                      )
    if categorized_activity_data is not None:
        with open("categorized.json", "w") as out:
            out.write(json.dumps(categorized_activity_data
                                 , indent=4
                                 )
                      )
    print(
        " ====================================================\n| This is just a NetworkSage test sample, so we're quitting now. |\n ====================================================")
    return None  # for testing only!


def test_destination_analysis(destination, via_slack=False):
    """In this case we are only passed a destination:port string. If we know the destination, we should return (as JSON)
        that it is known, and pass back the Destination's metadata at that time. Do the same for Destinations where we
        know information about one of its parents (try to reuse logic found elsewhere that does this). If we DON'T know
        the destination, collect OSINT about it from (as of now):
            + Internet search results
            + WHOIS
            + DNS information (specifically, if it has an IP address)
        Once OSINT is collected, use that information and make a decision about what we think about the destination (if
        at all possible, push it through our existing pipeline of analyses to keep code in one place), and return it to
        the user in JSON format.
    """
    evidence = evidence_collector.EvidenceCollector()
    safe_link = utilities.create_safe_link(destination)
    summary_data = dict()
    msg = "`Destination Analyzer`\n"
    if via_slack:
        msg += "Analyzing " + safe_link
        sent = slack.send_new_message(channel="#some_channel", message_text=msg)
        evidence.other_metadata["channel_id"] = sent["channel"]
        evidence.other_metadata["msg_id"] = sent["ts"]
        evidence.other_metadata["mode"] = "destination_analysis"
    summary_data = display.get_destination_summary(destination
                                                   , incoming_evidence=evidence
                                                   , via_slack=via_slack
                                                   )
    msg = ""
    for item in summary_data.keys():
        if item == "known":
            msg += "`" + safe_link + "`"
            if summary_data[item]:
                msg += " is a site *known* by _NetworkSage_. Details are as follows:\n"
            else:
                msg += " is *not known* by _NetworkSage_. However, OSINT analysis of the site leads us to believe the following:\n"
        else:
            for site_data in summary_data[item]:
                msg += "*" + site_data.capitalize() + ":* "
                if site_data == "details":
                    msg += "\n```" + summary_data[item][site_data] + "```"
                else:
                    msg += summary_data[item][site_data] + "\n"
    msg += "\nHowever, just searching for a destination is only provides a small part of the whole story. In order to get the most accurate knowledge about this destination and its effect to your organization, please submit a sample of network activity that contains this and nearby activity (usually capturing the activity between a minute before and a minute after will suffice)."
    if via_slack:
        slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
    else:
        print(msg)
    with open("destination_summary.json", "w") as out:
        out.write(json.dumps(summary_data
                             , indent=4
                             )
                  )


def do_full_test(args):
    print("Full test")
    return_data_dict = dict()
    results = scrape.load_twitter_results("tmp_twitter_jerdeview.txt")
    if "twitter" in return_data_dict.keys():
        return_data_dict["twitter"] += [scrape.parse_twitter_results(results)]
    else:
        return_data_dict["twitter"] = [scrape.parse_twitter_results(results)]
    if len(return_data_dict["twitter"]) == 0:
        print("No Twitter results contained valid links")
    twitter_results = return_data_dict["twitter"][0]  # .popleft() # take the first entry we see
    input_source = "twitter"
    # print("Results from", input_source+":", results.items())
    user_identifier = None
    success = True
    collected_evidence = None
    for key in twitter_results:  # key should be a username or user identifier
        user_identifier = key
        for result in twitter_results[key]:
            for link in result["links"]:
                msg = "`TEST (not new, please disregard!)`\n"
                safe_link = link.replace(".", "[.]")
                msg += "Found an item from " + input_source + " user " + user_identifier + " (" + safe_link + ")."
                evidence = evidence_collector.EvidenceCollector()
                if args.slack:
                    msg += "\nOriginal tweet content:\n```" + result["tweet"] + "\n```\n"
                    collected_evidence = slack.send_notice(msg, args, link, result, evidence)
                    if collected_evidence is None:
                        success = False
                else:
                    collected_evidence = analysis.collect_sandbox_evidence(False, "automated", link, result, args.slack,
                                                                           evidence,
                                                                           channel=None, thread=None)
            quiet = True
            if not success or collected_evidence is None:
                print("Failed to work. Skipping analysis.")
                return collected_evidence
            else:
                evidence = collected_evidence
            for destination in evidence.destination_data.keys():
                if not quiet:
                    print("----------------------------------------------------\nAll Evidence Collected for",
                          destination + ":")
                    for evidence_source in evidence.destination_data[destination].keys():
                        print(" ====================================================\n " + evidence_source + ":")
                        if evidence_source == "search_result_analysis":
                            item = evidence.destination_data[destination][evidence_source]
                            print(destination + " has been identified as", item.risk,
                                  item.category + ". Details are available.")
                            if len(item.domains_mentioned_in_security_results) > 0:
                                print("This destination also had other domains mentioned in its results:",
                                      item.domains_mentioned_in_security_results)
                        else:
                            print(evidence.destination_data[destination][evidence_source])
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
                slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
                return None
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
                slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
                return None
            with open("example_output2.txt", "w") as out:
                out.write(json.dumps(summary_data, indent=4))
                out.write(json.dumps(categorized_activity_data, indent=4))
            for item in ["verdict", "confidence", "summary", "details"]:
                msg += "*" + item.capitalize() + ":* " + summary_data[item] + "\n"
            slack.send_thread_reply(evidence.other_metadata["channel_id"], msg,
                                    evidence.other_metadata["msg_id"])

    print(
        " ====================================================\n| This is just a full test sample, so we're quitting now. |\n ====================================================")
    sys.exit(1)  # for testing only!
