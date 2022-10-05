"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import ast
import copy
import datetime
import logging
import re

import utilities
from activitygroup import activity_grouping
from inferences import inference_analysis
from interactivity import slack
from metadatascripts import retrieve_metadata, sandbox, authentication

logger = logging.getLogger("Analysis")

"""This module performs the overall analysis of a sample or some metadata. This is where final decisions are made for
    what to provide back to the user and (depending on how what tooling is using this file) whether additional analysis
    should occur.
"""


def analyze_all_evidence(evidence, via_slack):
    """Once all evidence is collected for a particular destination, it is time to determine what we truly think of it.
        For each destination (which is the key for the verdict dictionary), collect the following:
            + reason_text --> a set of snippets/sentences that describe why we
                              decided something
            + verdict --> a string
    """
    verdict = dict()  # a place to store our decision for a given destination
    verdict["sample_attributes"] = dict()
    verdict["destinations"] = dict()
    do_lookups = False

    msg = "Analyzing all collected evidence."
    if via_slack:
        slack.send_thread_reply(evidence.other_metadata["channel_id"], msg, evidence.other_metadata["msg_id"])
    else:
        logger.info(msg)
    if len(evidence.destination_data) == 0:
        return verdict  # nothing to analyze...
    if utilities.dns_lookups_working():
        do_lookups = True

    if "known_in_sample" in evidence.sample_metadata.keys():
        logger.info("Analyzing activity in this sample that is already known")
        analyze_known_activities(evidence.sample_metadata["known_in_sample"], verdict)

    """The above just captured a bunch of stuff for the sample that we should leverage. Now we should do more analysis
        of each destination.
    """
    for destination in evidence.destination_data.keys():
        if destination not in verdict["destinations"].keys():
            verdict["destinations"][destination] = dict()
            verdict["destinations"][destination]["full_destinations"] = evidence.destination_data[destination][
                "full_destinations"]
        if "reason_text" not in verdict["destinations"][destination].keys():
            verdict["destinations"][destination]["reason_text"] = set()
        logger.info("Analyzing evidence for " + str(destination))
        # process the rest of the evidence
        for evidence_source in evidence.destination_data[destination].keys():
            if evidence_source == "initial_osint_knowledge":
                analyze_from_initial_osint(evidence.destination_data[destination][evidence_source]
                                           , verdict["destinations"][destination]
                                           )
            elif evidence_source == "manual_sandbox_interesting_data":
                analyze_from_manual_sandbox(evidence.destination_data[destination][evidence_source]
                                            , verdict["destinations"][destination]
                                            )
            elif evidence_source == "unknown_destination_data":
                analyze_unknown_destination_flow_data(evidence.destination_data[destination][evidence_source]
                                                      , verdict["destinations"][destination]
                                                      )
            elif evidence_source == "search_result_analysis":
                verdict["destinations"][destination]["search_results"] = evidence.destination_data[destination][
                    evidence_source]
            elif evidence_source == "whois_data":
                analyze_whois_data(evidence.destination_data[destination][evidence_source]
                                   , verdict["destinations"][destination]
                                   , evidence.sample_metadata
                                   )
            elif evidence_source == "misp_warning_lists":
                verdict["destinations"][destination]["misp_warning_lists"] = evidence.destination_data[destination][
                    evidence_source]
            elif evidence_source == "full_destinations":
                current_destination_dict = None
                for dest_and_port_record in evidence.destination_data[destination][evidence_source]:
                    if dest_and_port_record["name_and_port"] == destination:
                        current_destination_dict = dest_and_port_record
                        break
                if current_destination_dict is not None:
                    # both of these items are guaranteed to be there, though they could be None (in weird cases)
                    verdict["destinations"][destination]["inferences"] = current_destination_dict["inferences"]
                    verdict["destinations"][destination]["activity_groups"] = current_destination_dict[
                        "activity_groups"]
                    try:
                        verdict["destinations"][destination]["initial_category"] = current_destination_dict[
                            "inferences"]
                    except:
                        verdict["destinations"][destination]["initial_category"] = "Suspicious Activity"
        if do_lookups and not utilities.destination_is_resolvable(destination):
            now = str(datetime.datetime.today())
            verdict["destinations"][destination]["has_IP"] = False
        else:
            verdict["destinations"][destination]["has_IP"] = True
        try:  # handle destination analysis cases
            if "inferences" not in verdict["destinations"][destination].keys() and verdict["destinations"][destination][
                "activity_groups"] == []:
                try:
                    verdict["destinations"][destination]["initial_category"] = evidence.destination_data[destination][
                        evidence_source].category
                except:
                    verdict["destinations"][destination]["initial_category"] = "Suspicious Activity"
        except:
            if "initial_category" not in verdict["destinations"][destination].keys():
                if "initial_category" in evidence.destination_data[destination].keys():
                    verdict["destinations"][destination]["initial_category"] = evidence.destination_data[destination][
                        "initial_category"]
                else:
                    verdict["destinations"][destination]["initial_category"] = "Suspicious Activity"
    for destination in verdict["destinations"].keys():
        logger.info("Evidence found for " + destination)
        for key in verdict["destinations"][destination].keys():
            if key in ["full_destinations", "misp_warning_lists"]:
                logger.info("\t" + str(key) + ":")
                for entry in verdict["destinations"][destination][key]:
                    logger.info("\t\t" + str(entry))
            elif key in ["search_results"]:
                logger.info("\t" + str(key) + ":")
                if verdict["destinations"][destination][key] is not None:
                    logger.info("\t\t" + str(verdict["destinations"][destination][key].__str__()))
            else:
                logger.info("\t"
                             + str(key)
                             + " --> "
                             + str(verdict["destinations"][destination][key])
                             )
    return verdict


def get_actions_dict_entry(proposed_actions_dict, destination, evidence=None):
    """The actions dictionary is useful to capture metadata around what we propose the user do. This returns an existing
        entry or creates a default entry for new destinations.
    """
    if destination not in proposed_actions_dict.keys():
        proposed_actions_dict[destination] = {"action": None
            , "title": None
            , "text": ""
            , "tags": dict()
            , "relevance": None
            , "why": ""
            , "confidence": ""
            , "raw_evidence": evidence
                                              }  # initialize defaults for dict
    return proposed_actions_dict[destination]


def semifinalize_categorization_of_suspicious_activity(verdict_collector_dict):
    """This function takes EVERYTHING we've learned (from all of our sources and interpretations) for destinations that
        don't have NetworkSage metadata and attempts to correctly categorize them based on everything we know. Once that
        is complete, it also attempts to explain (in language that would be accessible to a user who is aware of
        security terms but who isn't necessarily an expert) why the decisions were made. It is named "semifinalize"
        instead of "finalize" because we do one more detailed pass on these recategorizations to try to draw a more
        accurate and precise narrative for the user about the most interesting activity in the sample. If that narrative
        discovers that something was wrong (or has a higher or lower confidence), it will update them accordingly.
    """
    proposed_actions_dict = dict()  # store suggested action, title, text, tags, relevance, and all of the raw evidence
    for destination in verdict_collector_dict["destinations"].keys():
        dest_evidence = verdict_collector_dict["destinations"][destination]
        actions_for_dest = get_actions_dict_entry(proposed_actions_dict
                                                  , destination
                                                  , dest_evidence
                                                  )  # initialize defaults for dict
        # print(destination, "has an Initial Category of", dest_evidence["initial_category"])
        logger.info(str(destination) + " has an initial category of " + str(dest_evidence["initial_category"]))
        if dest_evidence["initial_category"] not in ["Suspicious Activity"]:
            actions_for_dest["raw_evidence"] = dest_evidence  # it's not suspicious activity, so capture and continue
            continue
        sus_dest_evidence = dest_evidence  # rename to make it clearer that we're only analyzing Sus sites here.
        for sus_name_and_port_evidence in sus_dest_evidence["full_destinations"]:
            # full port is stored in "full_destination" field of dest's dict
            dest_name_and_port = sus_name_and_port_evidence["name_and_port"]
            logger.info(
                " ====================================================\nPerforming semi-final categorization for "
                + sus_dest_evidence["initial_category"]
                + " "
                + destination
                + " ("
                + dest_name_and_port
                + ")"
                )
            inference_score = 0
            inference_descriptions = ""
            if "inferences" in sus_name_and_port_evidence.keys():
                inference_object = sus_name_and_port_evidence["inferences"]
                inference_score = inference_object.get_total_score()
                inference_descriptions = inference_object.get_descriptions_as_string()
            logger.info("Inference information for "
                         + dest_name_and_port
                         + ":"
                         )
            logger.info("\tTotal Score: "
                         + str(inference_score)
                         )
            logger.info("\tDescriptions: "
                         + inference_descriptions
                         )
            nonempty_search_results = False
            if "search_results" in sus_dest_evidence.keys() and sus_dest_evidence["search_results"] is not None:
                nonempty_search_results = True
                logger.info("Search results for "
                             + destination
                             + "\n\t"
                             + sus_dest_evidence["search_results"].final_text
                             )
            nonempty_misp_results = False
            misp_category = None
            misp_purpose = None  # assign to None so we have them always
            if "misp_warning_lists" in sus_dest_evidence.keys() and sus_dest_evidence["misp_warning_lists"] is not None:
                logger.info("Raw MISP results for "
                             + destination
                             )
                for wl in sus_dest_evidence["misp_warning_lists"]:
                    logger.info("\t"
                                 + str(wl.name)
                                 )
                nonempty_misp_results = True
                misp_category, misp_purpose = interpret_misp_warninglist_data(destination,
                                                                              sus_dest_evidence["misp_warning_lists"]
                                                                              )
            built_on_trusted = False
            if "inferences" in sus_name_and_port_evidence.keys() and "built_on_trusted" in inference_object.associated_inferences.keys():
                logger.info(dest_name_and_port + " is built on trusted.")
                built_on_trusted = True
            noip_commentary = "as of right now this destination does not have an IP address (though in the sample it did). This can indicate that it has been taken down by the hosting provider and/or registrar, which further elevates the chance that it is malicious."
            # filter out seclaritytruncated stuff so we don't accidentally review the lack of search results as bad.
            if destination.startswith("seclarityTruncated."):
                actions_for_dest["confidence"] = "High"
                actions_for_dest["why"] = ("We have "
                                           + actions_for_dest["confidence"]
                                           + " confidence that this site is exhibiting Common Activity in this sample. The site is something that the creators of NetworkSage have truncated to allow region-specific non-sensitive destinations to be treated as one destination."
                                           )
                relabel_destination_category(sus_name_and_port_evidence
                                             , "Common Activity"
                                             , actions_for_dest["why"]
                                             , actions_for_dest["confidence"]
                                             )
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
                continue  # short-circuit
            if inference_score <= -10:
                actions_for_dest["confidence"] = "High"
                actions_for_dest["why"] = ("We have "
                                           + actions_for_dest["confidence"]
                                           + " confidence that this site is exhibiting Common Activity in this sample. The site's activity is not interesting"
                                           )
                if nonempty_search_results:
                    if sus_dest_evidence["search_results"].score < 5:
                        actions_for_dest["why"] += ", and our search results agree."
                    else:
                        actions_for_dest["why"] += ", though our search results seem to disagree."
                elif nonempty_misp_results:
                    actions_for_dest["why"] += ", and our interpretation of publicly-available data agrees."
                relabel_destination_category(sus_name_and_port_evidence
                                             , "Common Activity"
                                             , actions_for_dest["why"]
                                             , actions_for_dest["confidence"]
                                             )
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
                continue  # short-circuit
            if nonempty_search_results and sus_dest_evidence["search_results"].risk is None:
                logger.info(
                    "***********\nNOTE: Setting risk to potentially malicious because it had NONE!\n**************")
                sus_dest_evidence["search_results"].risk = "Potentially Malicious"
            if nonempty_search_results:
                logger.info("Search-based score: "
                             + str(sus_dest_evidence["search_results"].score)
                             )
                logger.info("Search-based risk: "
                             + str(sus_dest_evidence["search_results"].risk)
                             )
            # handle all of the dests with Known Malicious search results or WHOIS results first.
            if ((nonempty_search_results and sus_dest_evidence["search_results"].risk == "Known Malicious")
                    or "phishing_by_whois" in sus_dest_evidence.keys()
            ):
                short_circuit = determine_if_known_malicious(sus_dest_evidence
                                                             , sus_name_and_port_evidence
                                                             , destination
                                                             , inference_score
                                                             , inference_descriptions
                                                             , actions_for_dest
                                                             , noip_commentary
                                                             )
                if short_circuit:
                    continue
            elif ((nonempty_search_results and sus_dest_evidence["search_results"].risk in [
                "Potentially Malicious",
                "Likely Malicious"
            ]
                  )
                  or (not nonempty_search_results and not nonempty_misp_results)
            ):
                short_circuit = determine_if_potentially_malicious(sus_dest_evidence
                                                                   , sus_name_and_port_evidence
                                                                   , destination
                                                                   , inference_score
                                                                   , inference_descriptions
                                                                   , actions_for_dest
                                                                   , noip_commentary
                                                                   , built_on_trusted
                                                                   , nonempty_search_results
                                                                   , nonempty_misp_results
                                                                   )
                if short_circuit:
                    continue
            elif (
                    (nonempty_search_results and "Benign" in sus_dest_evidence["search_results"].risk)
                    or nonempty_misp_results
            ):
                if sus_dest_evidence["search_results"] is not None:
                    initial_risk = sus_dest_evidence["search_results"].risk
                    initial_category = sus_dest_evidence["search_results"].category
                    details_text = sus_dest_evidence["search_results"].final_text
                else:
                    initial_risk = "Benign"
                    if misp_purpose is None:
                        initial_category = "Known site"
                    else:
                        initial_category = misp_purpose
                    details_text = ("This site appeared in "
                                    + str(len(sus_dest_evidence["misp_warning_lists"]))
                                    + " lists that are curated to capture commonly-seen activity that erroneously ends up triggering common techniques used to identify malicious behavior:\n"
                                    )
                    count = 1
                    for entry in sus_dest_evidence["misp_warning_lists"]:
                        if entry.name.startswith("List of "):
                            entry.name = entry.name[8:]
                        details_text += (str(count)
                                         + ". "
                                         + entry.name
                                         + "\n"
                                         )
                        count += 1
                parent_domain_commentary = ""
                if "parent_search_results" in sus_dest_evidence.keys():
                    parent_domain_commentary = " for the parent domain of this subdomain (since we believe it should be trusted at the same level)"
                determine_if_actually_benign(sus_dest_evidence
                                             , sus_name_and_port_evidence
                                             , destination
                                             , inference_object
                                             , inference_score
                                             , inference_descriptions
                                             , actions_for_dest
                                             , parent_domain_commentary
                                             , misp_purpose
                                             , initial_risk
                                             , initial_category
                                             , details_text
                                             )
                if inference_score >= 5:
                    if (
                            (nonempty_search_results and sus_dest_evidence["search_results"].score > 2)
                            or misp_purpose == "Semi-Popular Site"
                    ):
                        if "likely_c2" in inference_object.associated_inferences:
                            new_category = "Common Activity"
                            actions_for_dest["confidence"] = "Medium"
                            actions_for_dest["why"] = ("We have "
                                                       + actions_for_dest["confidence"]
                                                       + " confidence that this site is Common Activity in this sample, perhaps performing analytics or non-malicious tracking/reporting. "
                                                       + inference_descriptions
                                                       + " Our OSINT analysis"
                                                       + parent_domain_commentary
                                                       + ", which we've interpreted as identifying the site as a "
                                                       + initial_risk
                                                       + " "
                                                       + initial_category
                                                       + ", mostly agrees. Additional details are as follows. "
                                                       + details_text
                                                       )
                        else:
                            new_category = "Attack Vector"
                            actions_for_dest["confidence"] = "Medium"
                            actions_for_dest["why"] = ("We have "
                                                       + actions_for_dest["confidence"]
                                                       + " confidence that this site is acting as an Attack Vector in this sample. "
                                                       + inference_descriptions
                                                       + " Our OSINT analysis"
                                                       + parent_domain_commentary
                                                       + ", which we've interpreted as identifying the site as a "
                                                       + initial_risk
                                                       + " "
                                                       + initial_category
                                                       + ", mostly agrees. Additional details are as follows. "
                                                       + details_text
                                                       + "\nIf there is Malicious or Suspicious activity in this sample, this site may be the way that behavior was hosted and served to the user."
                                                       )
                        relabel_destination_category(sus_name_and_port_evidence
                                                     , new_category
                                                     , actions_for_dest["why"]
                                                     , actions_for_dest["confidence"]
                                                     )
                        activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                           , actions_for_dest["why"]
                                                                           )
                    else:
                        actions_for_dest["confidence"] = "Medium-High"
                        actions_for_dest["why"] = ("We have "
                                                   + actions_for_dest["confidence"]
                                                   + " confidence that this site is acting as Common Activity in this sample. "
                                                   + inference_descriptions
                                                   + " Our OSINT analysis"
                                                   + parent_domain_commentary
                                                   + ", which we've interpreted as identifying the site as a "
                                                   + initial_risk
                                                   + " "
                                                   + initial_category
                                                   + ", mostly agrees. Additional details are as follows. "
                                                   + details_text
                                                   + "\n"
                                                   + enrich_with_temporal_data(destination
                                                                               , sus_dest_evidence
                                                                               , sus_name_and_port_evidence
                                                                               )
                                                   )
                        relabel_destination_category(sus_name_and_port_evidence
                                                     , "Common Activity"
                                                     , actions_for_dest["why"]
                                                     , actions_for_dest["confidence"]
                                                     )
                        activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                           , actions_for_dest["why"]
                                                                           )
                elif 1 <= inference_score <= 4:
                    actions_for_dest["confidence"] = "Medium-High"
                    actions_for_dest["why"] = ("We have "
                                               + actions_for_dest["confidence"]
                                               + " confidence that this site is acting as Common Activity in this sample. "
                                               + inference_descriptions
                                               + " Our OSINT analysis"
                                               + parent_domain_commentary
                                               + ", which we've interpreted as identifying the site as a "
                                               + initial_risk
                                               + " "
                                               + initial_category
                                               + ", mostly agrees. Additional details are as follows. "
                                               + details_text
                                               + "\n"
                                               + enrich_with_temporal_data(destination
                                                                           , sus_dest_evidence
                                                                           , sus_name_and_port_evidence
                                                                           )
                                               )
                    relabel_destination_category(sus_name_and_port_evidence
                                                 , "Common Activity"
                                                 , actions_for_dest["why"]
                                                 , actions_for_dest["confidence"]
                                                 )
                    activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                       , actions_for_dest["why"]
                                                                       )
                else:  # 0 or lower inference score
                    actions_for_dest["confidence"] = "High"
                    actions_for_dest["why"] = ("We have "
                                               + actions_for_dest["confidence"]
                                               + " confidence that this site is acting as Common Activity in this sample. There is no evidence of this site doing anything interesting in this sample. "
                                               + inference_descriptions
                                               + " Our OSINT analysis"
                                               + parent_domain_commentary
                                               + ", which we've interpreted as identifying the site as a "
                                               + initial_risk
                                               + " "
                                               + initial_category
                                               + ", mostly agrees. Additional details are as follows. "
                                               + details_text
                                               + "\n"
                                               + enrich_with_temporal_data(destination
                                                                           , sus_dest_evidence
                                                                           , sus_name_and_port_evidence
                                                                           )
                                               )
                    relabel_destination_category(sus_name_and_port_evidence
                                                 , "Common Activity"
                                                 , actions_for_dest["why"]
                                                 , actions_for_dest["confidence"]
                                                 )
                    activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                       , actions_for_dest["why"]
                                                                       )
                continue
            elif not nonempty_search_results and not nonempty_misp_results:
                if built_on_trusted and "actual_page_loaded" in inference_object.associated_inferences:
                    actions_for_dest["confidence"] = "Medium"
                    likely_new_category = "Malicious Activity"
                    exhibition_text = (" confidence that this site is exhibiting "
                                       + likely_new_category
                                       + " in this sample. "
                                       )
                    actions_for_dest["why"] = ("We have "
                                               + actions_for_dest["confidence"]
                                               + exhibition_text
                                               + inference_descriptions
                                               )
                    relabel_destination_category(sus_name_and_port_evidence
                                                 , likely_new_category
                                                 , actions_for_dest["why"]
                                                 , actions_for_dest["confidence"]
                                                 )
                    activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                       , actions_for_dest["why"]
                                                                       )
            else:
                try:
                    logger.info("Unhandled destination "
                                 + destination
                                 + " with the following details:"
                                 + "\n\tSearch Results Risk:"
                                 + sus_dest_evidence["search_results"].risk
                                 + "\n\tSearch Results Category:"
                                 + sus_dest_evidence["search_results"].category
                                 + "\n\tSearch Results Score:"
                                 + str(sus_dest_evidence["search_results"].score)
                                 + "\n\tInferences Score:"
                                 + str(inference_score)
                                 )
                except:
                    try:
                        logger.info("Unhandled destination, likely without search results. Other data: ")
                        for wl in sus_dest_evidence["misp_warning_lists"]:
                            logger.info("\t"
                                         + str(wl.name)
                                         )
                    except:
                        logger.info("Completely unhandled destination " + destination)
            actions_for_dest["raw_evidence"] = sus_dest_evidence
    return proposed_actions_dict


def infuse_decisions_with_clustering(verdict, proposed_actions_dict, sample_metadata):
    """Once we're at this point, we know everything about each of the activities in the sample. We know how they're
        grouped, what we think of them, and what they seem to have done. They're also categorized and ready for display.
        The purpose of this function is to leverage clusters of groups of activities (things that end almost
        simultaneously) to further strengthen or refute what we believe about our semi-finalized decisions. If we find
        that something previously captured is more or less compelling, we will update accordingly and capture the
        high-level details within the metadata for the sample itself. If there are no clusters, we won't do much of
        anything here.
    """
    # look at activity within each cluster
    activity_groups = []
    dest_and_port_records = dict()  # easier way to work with this instead of requesting over and over
    for dest in proposed_actions_dict.keys():
        """We need ALL activity groups, even if we previously found them uninteresting, because these may play an Attack
            Vector or other role in this sample that we didn't explicitly know.
        """
        # print("Destination", dest, "with proposed actions:", proposed_actions_dict[dest])
        try:
            for dest_and_port in proposed_actions_dict[dest]["raw_evidence"]["full_destinations"]:
                try:
                    dest_and_port_records[dest_and_port["name_and_port"]] = dest_and_port
                    activity_groups += dest_and_port["activity_groups"]
                except:
                    logger.info("Couldn't find activity group for destination " + dest)
                    continue
        except:
            logger.info("Couldn't find raw evidence or full destinations...")
            continue
    ordered_clusters = inference_analysis.get_clusters_by_start_time(activity_groups)
    interesting_clusters = identify_interesting_clusters(ordered_clusters, activity_groups)
    interesting_subclusters = inference_analysis.collect_interesting_subclusters(interesting_clusters, ordered_clusters)
    if "inferences" in sample_metadata.keys():
        all_inferences = sample_metadata["inferences"]
    else:
        all_inferences = dict()
    destinations_to_update = []
    had_phishing = False
    had_impact = False
    had_attack_vector = False
    topic = inference_analysis.discover_topic(ordered_clusters
                                              , interesting_clusters
                                              , interesting_subclusters
                                              , verdict
                                              , activity_groups
                                              )
    destinations_to_update += inference_analysis.discover_phishing(dest_and_port_records
                                                                   , ordered_clusters
                                                                   , interesting_clusters
                                                                   , topic
                                                                   , verdict
                                                                   )
    if len(destinations_to_update) > 0:
        had_phishing = True
    num_updates = len(destinations_to_update)
    if num_updates > 0:  # we can only have an impact if we have phishing (in future, expand to other impacts!)
        destinations_to_update += inference_analysis.discover_impact(proposed_actions_dict
                                                                     , ordered_clusters
                                                                     , interesting_clusters
                                                                     )
        if len(destinations_to_update) - num_updates != 0:
            had_impact = True
        num_updates = len(destinations_to_update)  # capture for next review
        destinations_to_update += inference_analysis.discover_attack_vector(proposed_actions_dict
                                                                            , ordered_clusters
                                                                            , interesting_clusters
                                                                            )
        if len(destinations_to_update) - num_updates != 0:
            had_attack_vector = True
    if topic is not None and (had_phishing or had_impact):
        """When we have either phishing or an impact, that means we need to make sure that we're not incorrectly
            labeling any of those sites as the brand being targeted!
        """
        for update_record in destinations_to_update:
            try:
                if "root_domain_by_whois" in verdict["destinations"][update_record["destination"]].keys():
                    rdbw = verdict["destinations"][update_record["destination"]]["root_domain_by_whois"]
                    if rdbw is None:
                        rdbw = update_record["destination"]
                else:
                    rdbw = update_record["destination"]
                if topic[1] == rdbw:  # attempt to avoid labeling the phishing site as the topic
                    logger.info(
                        "Removed suspected topic of " + str(topic) + " because it matched a phishing or impact site.")
                    topic = None
                    break
            except:
                continue
    if topic is None:
        # try one more time, now with knowledge of suspected phishing and impact
        topic = inference_analysis.discover_topic(ordered_clusters
                                                  , interesting_clusters
                                                  , interesting_subclusters
                                                  , verdict
                                                  , activity_groups
                                                  , destinations_to_update
                                                  )
    nonmalicious_pageloads = inference_analysis.collect_nonmalicious_pageloads(verdict,
                                                                               all_inferences,
                                                                               activity_groups
                                                                               )
    if topic is None and not had_phishing and not had_impact:
        """Try again, this time by looking at Attack Vectors or Common Activities that are identified as page loads and
            seeing if there's any activity RIGHT before it that happens for the first time and is Sus or Mal. Note that
            if we find a topic here, we likely need to go back through and hit phishing and impact again.
        """
        possible_phishes, topic = inference_analysis.find_topic_from_pageloads(nonmalicious_pageloads,
                                                                               all_inferences,
                                                                               activity_groups
                                                                               )
        if len(possible_phishes) > 0:
            had_phishing = True
            destinations_to_update += possible_phishes
    if topic is not None:
        sample_metadata["suspected_topic"] = topic
    if had_attack_vector:
        sample_metadata["attack_vector_detected"] = True
    if had_phishing:
        sample_metadata["phishing_detected"] = True
    if had_impact:
        sample_metadata["impact_detected"] = True
    destinations_to_update = inference_analysis.guilty_by_association(destinations_to_update, activity_groups)
    destinations_to_update = inference_analysis.guilty_by_cluster(destinations_to_update, activity_groups)
    for destination_details in destinations_to_update:
        destination = destination_details["destination"]
        actions_for_dest = get_actions_dict_entry(proposed_actions_dict, destination)
        original_text = get_original_text_for_actions(actions_for_dest)
        if not had_attack_vector and "Attack Vector" in destination_details["site_purpose"]:
            proposed_attack_vector = destination_details
            proposed_attack_vector_invalidated = False  # identify if we prove that it couldn't have been the AV
            if had_phishing: # TODO: Other attack types need to be considered, such as CRX, drive-by, etc...
                for d in destinations_to_update:
                    try:
                        if d["site_purpose"] == "Phishing" and (
                                float(d["earliest_seen"]) <= float(proposed_attack_vector["earliest_seen"])
                        ):
                            logging.info("proposed attack vector "+proposed_attack_vector["destination"]
                                         + "(first seen at "
                                         + str(proposed_attack_vector["earliest_seen"])
                                         + ") can't be right, because it happens after phishing (first seen at "
                                         + str(d["earliest_seen"])
                                         + ")!"
                                         )
                            proposed_attack_vector_invalidated = True
                            break
                    except:
                        logging.warn("Something went wrong while trying to compare proposed attack vector and phishing site.")
            if not proposed_attack_vector_invalidated and had_impact:
                for d in destinations_to_update:
                    try:
                        if d["site_purpose"] == "Impact" and (
                                float(d["earliest_seen"]) <= float(proposed_attack_vector["earliest_seen"])
                        ):
                            logging.info("proposed attack vector "+proposed_attack_vector["destination"]
                                         + "(first seen at "
                                         + str(proposed_attack_vector["earliest_seen"])
                                         + ") can't be right, because it happens after Impact (first seen at "
                                         + str(d["earliest_seen"])
                                         + ")!"
                                         )
                            proposed_attack_vector_invalidated = True
                            break
                    except:
                        logging.warn("Something went wrong while trying to compare proposed attack vector and Impact site.")
            if not proposed_attack_vector_invalidated:
                had_attack_vector = True
                sample_metadata["attack_vector_detected"] = True
                sample_metadata["suspected_attack_vector"] = destination
            else:  #we've invalidated it as an AV, so capture that
                destination_details["site_purpose"] = "Common Activity"
                destination_details["category"] = "Common Activity"
                destination_details["confidence"] = "High"
        try:
            destination_info = dest_and_port_records[destination_details["dest_and_port"]]
        except:
            destination_info = None
            logger.warning("Something went wrong while trying to get destination info.")
        relabel_destination_category(destination_info
                                     , destination_details["category"]
                                     , (destination_details["site_purpose"]
                                        + original_text
                                        )
                                     , destination_details["confidence"]
                                     )
    uninteresting_pageloads = inference_analysis.identify_uninteresting_pageloads(nonmalicious_pageloads,
                                                                                  destinations_to_update
                                                                                  )
    sample_metadata["uninteresting_pageloads"] = copy.deepcopy(uninteresting_pageloads)  # grab this for use in summary
    uninteresting_attackvectors = inference_analysis.identify_uninteresting_attackvectors(dest_and_port_records,
                                                                                          all_inferences,
                                                                                          activity_groups,
                                                                                          destinations_to_update
                                                                                        )
    uninteresting_pageloads.update(uninteresting_attackvectors)  # combine these dicts at this point
    for dest in uninteresting_pageloads.keys():
        earliest_group = uninteresting_pageloads[dest][0]
        destination = utilities.dest_without_port(earliest_group.destination_and_port)
        actions_for_dest = get_actions_dict_entry(proposed_actions_dict, destination)
        original_text = get_original_text_for_actions(actions_for_dest)
        try:
            destination_info = dest_and_port_records[earliest_group.destination_and_port]
        except:
            destination_info = None
            logger.warning("Something went wrong while trying to get destination info.")
        category = "Common Activity"
        purpose = "This site does not seem to be related to anything interesting in this sample. "
        confidence = "Medium"
        logger.info("Relabeling " + destination + " as " + category)
        relabel_destination_category(destination_info
                                     , category
                                     , (purpose + original_text)
                                     , confidence
                                     )


def get_original_text_for_actions(actions_for_dest):
    """Gets the correct original text from a site that we believe we have actions to recommend.
    """
    original_text = ""
    if "text" in actions_for_dest and len(actions_for_dest["text"]) > 0:
        original_text = actions_for_dest["text"]
    elif "why" in actions_for_dest and len(actions_for_dest["why"]) > 0:
        original_text = actions_for_dest["why"]
    return original_text


def identify_interesting_clusters(ordered_clusters, activity_groups):
    """Interesting clusters are defined as those that have destinations inside of them that have been identified as
        Malicious or having Impact. Returns only the cluster IDs (as a list of ints) that match these cases. Moreover,
        we include the unclustered (-1) if there are activities fitting this description in those.
    """
    interesting = []
    interesting_categories = ["Malicious Activity", "Impact"]
    for cluster in ordered_clusters:
        for g in ordered_clusters[cluster]:
            if g.category in interesting_categories:
                interesting += [cluster]
                break
    for group in activity_groups:
        if group.associated_cluster == -1:
            if group.category in interesting_categories:
                interesting += [group.associated_cluster]
                break
    return interesting


def enrich_with_closed_session_info(sus_dest_evidence):
    """Closed sessions are 100% not interesting in the current sample, though they MAY have been in a time period that
        ended before this sample. If there was a closed session, return some useful text for the user. Otherwise, return
        an empty string.
    """
    text = ""
    if "has_closed_session_only" in sus_dest_evidence.keys() and sus_dest_evidence["has_closed_session_only"]:
        text = "All we've seen for this site in this sample is a closed session, which *strongly* suggests that nothing happened to this site here. It may be a remnant of a previous session (for example, from something that occurred before this sample started)."
    return text


def determine_if_known_malicious(sus_dest_evidence, sus_name_and_port_evidence, destination, inference_score,
                                 inference_descriptions,
                                 actions_for_dest, noip_commentary):
    """If the interpretation of our Search results about a (currently) Suspicious Activity leads us to believe that it's
        actually known malicious, this function attempts to confirm or deny that verdict based on all of the other
        evidence we have collected. The end goal will be to recategorize each site (when appropriate) and update why we
        believe that the recategorization is correct. Note that some cases should stop our analysis from going any
        farther for this site; these are captured by returning True.
    """
    if inference_score >= 5:
        # first check looks to see if we have WHOIS, essentially. Second looks for more accurate date that comes from a private sample. Third looks for fallback.
        if (
                ("created_to_captured" not in sus_dest_evidence.keys()
                 and "created_to_now" not in sus_dest_evidence.keys()
                )
                or
                ("created_to_captured" in sus_dest_evidence.keys()
                 and sus_dest_evidence["created_to_captured"].days >= (365 * 5)
                )
                or
                ("created_to_now" in sus_dest_evidence.keys()
                 and sus_dest_evidence["created_to_now"].days >= (365 * 5)
                )
        ):
            if "phishing_by_whois" in sus_dest_evidence.keys():
                actions_for_dest["confidence"] = "High"
                actions_for_dest["why"] = (
                        enrich_with_temporal_data(destination
                                                  , sus_dest_evidence
                                                  , sus_name_and_port_evidence
                                                  )
                        + "The activity in this sample indicates the following. "
                        + inference_descriptions
                )
                relabel_destination_category(sus_name_and_port_evidence
                                             , "Malicious Activity"
                                             , actions_for_dest["why"]
                                             , actions_for_dest["confidence"]
                                             )
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
                return True
            elif sus_dest_evidence["search_results"].total_results >= 1000 and sus_dest_evidence["has_IP"]:
                actions_for_dest["confidence"] = "Medium"
                actions_for_dest["why"] = (
                        "Despite our Internet search results being confident that this site is malicious, we actually think that it was labeled as such because it is often seen around malicious behavior (such as resources that are loaded to impersonate a page). The activity in this sample indicates the following. "
                        + inference_descriptions
                        + " Our Internet search results say the following. "
                        + sus_dest_evidence["search_results"].final_text
                        + "\n"
                        + enrich_with_temporal_data(destination
                                                    , sus_dest_evidence
                                                    , sus_name_and_port_evidence
                                                    )
                )
                relabel_destination_category(sus_name_and_port_evidence
                                             , "Common Activity"
                                             , actions_for_dest["why"]
                                             , actions_for_dest["confidence"]
                                             )
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
                return True
        actions_for_dest["confidence"] = "High"
        actions_for_dest["action"] = "labelDestination"
        actions_for_dest["text"] = ("We have "
                                    + actions_for_dest["confidence"]
                                    + " confidence that this site is exhibiting Malicious Activity in this sample. "
                                    + inference_descriptions
                                    + " In addition, Internet search results agree. "
                                    + sus_dest_evidence["search_results"].final_text
                                    + "\n"
                                    + enrich_with_temporal_data(destination
                                                                , sus_dest_evidence
                                                                , sus_name_and_port_evidence
                                                                )
                                    )
        relabel_destination_category(sus_name_and_port_evidence
                                     , "Malicious Activity"
                                     , actions_for_dest["text"]
                                     , actions_for_dest["confidence"]
                                     )
        activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                           , actions_for_dest["text"]
                                                           )
    elif -5 <= inference_score <= 4:
        if (
                ("created_to_captured" not in sus_dest_evidence.keys()
                 and "created_to_now" not in sus_dest_evidence.keys()
                )
                or
                ("created_to_captured" in sus_dest_evidence.keys()
                 and sus_dest_evidence["created_to_captured"].days >= (365 * 5)
                )
                or
                ("created_to_now" in sus_dest_evidence.keys()
                 and sus_dest_evidence["created_to_now"].days >= (365 * 5)
                )
        ):
            if "phishing_by_whois" in sus_dest_evidence.keys():
                actions_for_dest["confidence"] = "Medium"
                actions_for_dest["why"] = (
                        enrich_with_temporal_data(destination
                                                  , sus_dest_evidence
                                                  , sus_name_and_port_evidence
                                                  )
                        + "The activity in this sample indicates the following. "
                        + inference_descriptions
                )
                relabel_destination_category(sus_name_and_port_evidence
                                             , "Malicious Activity"
                                             , actions_for_dest["why"]
                                             , actions_for_dest["confidence"]
                                             )
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
                return True
            elif sus_dest_evidence["search_results"].total_results >= 1000 and sus_dest_evidence["has_IP"]:
                actions_for_dest["confidence"] = "Medium"
                actions_for_dest[
                    "why"] = "Despite our Internet search results being confident that this site is malicious, we actually think that it was labeled as such because it "
                if "actual_page_loaded" in sus_name_and_port_evidence["inferences"].associated_inferences.keys():
                    actions_for_dest["why"] += "may be an Attack Vector used to load malicious behavior. "
                else:
                    actions_for_dest[
                        "why"] += "is often seen around malicious behavior (such as resources used to impersonate a site). "
                actions_for_dest["why"] += ("The activity in this sample indicates the following. "
                                            + inference_descriptions
                                            + enrich_with_closed_session_info(sus_dest_evidence)
                                            + " Our Internet search results say the following. "
                                            + sus_dest_evidence["search_results"].final_text
                                            )
                if "actual_page_loaded" in sus_dest_evidence[
                    "inferences"].associated_inferences.keys():  # more likely to be Attack Vector
                    # move to Attack Vectors or (TODO, if possible) Common Activity
                    relabel_destination_category(sus_name_and_port_evidence
                                                 , "Attack Vector"
                                                 , actions_for_dest["why"]
                                                 , actions_for_dest["confidence"]
                                                 )
                else:  # more likely to be Common Activity
                    relabel_destination_category(sus_name_and_port_evidence
                                                 , "Common Activity"
                                                 , actions_for_dest["why"]
                                                 , actions_for_dest["confidence"]
                                                 )
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
            else:
                actions_for_dest["confidence"] = "Medium"
                actions_for_dest["why"] = (enrich_with_temporal_data(destination
                                                                     , sus_dest_evidence
                                                                     , sus_name_and_port_evidence
                                                                     )
                                           + " Here is more information for you to review. The activity in this sample indicates the following. "
                                           + inference_descriptions
                                           + enrich_with_closed_session_info(sus_dest_evidence)
                                           + " Our Internet search results say the following. "
                                           + sus_dest_evidence["search_results"].final_text
                                           )
                if not sus_dest_evidence["has_IP"]:
                    actions_for_dest["why"] = (
                            " Our Internet search results seem to be confident that this site is malicious. Additionally, "
                            + noip_commentary
                            + " "
                            + actions_for_dest["why"]
                    )
                    # move to Malicious Activity
                    relabel_destination_category(sus_name_and_port_evidence
                                                 , "Malicious Activity"
                                                 , actions_for_dest["why"]
                                                 , actions_for_dest["confidence"]
                                                 )
                else:
                    actions_for_dest["why"] = (
                            "Despite our Internet search results being confident that this site is malicious, we're unsure of its purpose. "
                            + actions_for_dest["why"]
                    )
                    activity_grouping.update_confidence_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                        , actions_for_dest["confidence"]
                                                                        )
                    # leave in Suspicious Activity group
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
        else:
            likely_new_category = "Malicious Activity"
            closed_session_text = enrich_with_closed_session_info(sus_dest_evidence)
            if len(closed_session_text) > 0:
                likely_new_category = "Suspicious Activity"
                actions_for_dest["confidence"] = "Medium"
                actions_for_dest["action"] = ""
                actions_for_dest["text"] = ("We have "
                                            + actions_for_dest["confidence"]
                                            + " confidence that this site is *not* exhibiting any Malicious Activity in this sample. "
                                            + closed_session_text
                                            + "\n"
                                            + enrich_with_temporal_data(destination
                                                                        , sus_dest_evidence
                                                                        , sus_name_and_port_evidence
                                                                        )
                                            )
            else:
                actions_for_dest["confidence"] = "Medium-High"
                actions_for_dest["action"] = "labelDestination"
                actions_for_dest["text"] = ("We have "
                                            + actions_for_dest["confidence"]
                                            + " confidence that this site is exhibiting "
                                            + likely_new_category
                                            + " in this sample. "
                                            + inference_descriptions
                                            + " In addition, Internet search results agree. "
                                            + sus_dest_evidence["search_results"].final_text
                                            + "\n"
                                            + enrich_with_temporal_data(destination
                                                                        , sus_dest_evidence
                                                                        , sus_name_and_port_evidence
                                                                        )
                                            )
            relabel_destination_category(sus_name_and_port_evidence
                                         , likely_new_category
                                         , actions_for_dest["text"]
                                         , actions_for_dest["confidence"]
                                         )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["text"]
                                                               )
    else:
        if "phishing_by_whois" in sus_dest_evidence.keys():
            actions_for_dest["confidence"] = "Low"
            actions_for_dest["why"] = (
                    enrich_with_temporal_data(destination
                                              , sus_dest_evidence
                                              , sus_name_and_port_evidence
                                              )
                    + "The activity in this sample indicates the following. "
                    + inference_descriptions
                    + " It's possible that while there was a known phishing site in this sample, the site was already down or was not interacted with in a way that would cause impact."
            )
            relabel_destination_category(sus_name_and_port_evidence
                                         , "Malicious Activity"
                                         , actions_for_dest["why"]
                                         , actions_for_dest["confidence"]
                                         )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["why"]
                                                               )
        actions_for_dest["confidence"] = "Medium"
        actions_for_dest["why"] = (
                "Despite our Internet search results being confident that this site is malicious, we're really unsure of its purpose. "
                + enrich_with_temporal_data(destination
                                            , sus_dest_evidence
                                            , sus_name_and_port_evidence
                                            )
                + " The activity in this sample indicates the following. "
                + inference_descriptions
                + " Our Internet search results say the following."
                + sus_dest_evidence["search_results"].final_text
        )
        activity_grouping.update_confidence_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                            , actions_for_dest["confidence"]
                                                            )
        activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                           , actions_for_dest["why"]
                                                           )
        # leave in Suspicious Activity group
    return True  # don't do any of the other logic


def determine_if_potentially_malicious(sus_dest_evidence, sus_name_and_port_evidence, destination, inference_score,
                                       inference_descriptions, actions_for_dest, noip_commentary, built_on_trusted,
                                       nonempty_search_results, nonempty_misp_results):
    """If the interpretation of our Search results about a (currently) Suspicious Activity leads us to believe that it's
        potentially malicious, this function attempts to confirm or deny that verdict based on all of the other evidence
        we have collected. The end goal will be to recategorize each site (when appropriate) and update why we believe
        that the recategorization is correct. Note that some cases should stop our analysis from going any farther for
        this site; these are captured by returning True.
    """
    try:
        all_inferences = sus_name_and_port_evidence["inferences"].associated_inferences
    except:
        all_inferences = []
    search_interpretation = ""
    if nonempty_search_results:
        search_interpretation = sus_dest_evidence["search_results"].final_text
    (relevant_datetime, age_as_days) = get_age_tuple(sus_dest_evidence)
    if "parent_search_results" in sus_dest_evidence.keys() and inference_score < 10:
        search_data = sus_dest_evidence["search_results"]
        if search_data.risk in ["Benign", "Likely Benign"]:
            rdbw = sus_dest_evidence["root_domain_by_whois"]
            likely_new_category = "Common Activity"
            confidence = "Medium"
            actions_for_dest["text"] = ("We have "
                                        + confidence
                                        + " confidence that this site is uninteresting in this sample. We believe this because its parent domain ("
                                        + rdbw
                                        + ") seems to be a "
                                        + search_data.risk
                                        + " site, and we believe that the current site is just part of that site (for example, resources from that site). "
                                        + inference_descriptions
                                        + " In addition, Internet search results mostly agree. "
                                        + search_interpretation
                                        )
            # recategorize as appropriate
            relabel_destination_category(sus_name_and_port_evidence
                                         , likely_new_category
                                         , actions_for_dest["text"]
                                         , confidence
                                         )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["text"]
                                                               )
    if inference_score >= 10:
        if (
                (nonempty_search_results and sus_dest_evidence["search_results"].score > 5)
                or (not nonempty_search_results and not nonempty_misp_results)
        ):
            actions_for_dest["action"] = "labelDestination"
            if nonempty_search_results and "Generic" not in sus_dest_evidence["search_results"].category:
                threat_type = sus_dest_evidence["search_results"].category
            else:
                threat_type = "Site"
            if built_on_trusted:
                actions_for_dest["title"] = ("Malicious "
                                             + threat_type
                                             + " Hosted on Trusted Cloud Hosting Domain"
                                             )
            else:
                actions_for_dest["title"] = ("Malicious "
                                             + threat_type
                                             )
            if not sus_dest_evidence["has_IP"]:
                actions_for_dest["confidence"] = "High"
            else:
                actions_for_dest["confidence"] = "Medium-High"
            likely_new_category = "Malicious Activity"
            exhibition_text = (" confidence that this site is exhibiting "
                               + likely_new_category
                               + " in this sample. "
                               )
            if "actual_page_loaded" in all_inferences and "likely_attackvector" in all_inferences:
                if "has_autofill_form" not in all_inferences:
                    actions_for_dest["title"] = ("Attack Vector associated with Malicious Activity")
                    exhibition_text = (" confidence that this site is serving malicious content in this sample. "
                                       )
            if nonempty_search_results:
                search_interpretation = " In addition, Internet search results mostly agree. " + search_interpretation
            actions_for_dest["text"] = ("We have "
                                        + actions_for_dest["confidence"]
                                        + exhibition_text
                                        + inference_descriptions
                                        + search_interpretation
                                        + "\n"
                                        + enrich_with_temporal_data(destination
                                                                    , sus_dest_evidence
                                                                    , sus_name_and_port_evidence
                                                                    )
                                        )
            relabel_destination_category(sus_name_and_port_evidence
                                         , likely_new_category
                                         , actions_for_dest["text"]
                                         , actions_for_dest["confidence"]
                                         )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["text"]
                                                               )
        else:  # search results scored it a 5
            actions_for_dest["confidence"] = "Medium-High"
            if len(inference_descriptions) == 0:
                if nonempty_search_results:
                    search_interpretation = (
                                " Our Internet search results, however, seem to think it is an interesting destination. "
                                + search_interpretation
                                )
                actions_for_dest["why"] = (
                        "The activity for this destination doesn't show anything of interest in this sample. "
                        + search_interpretation
                )
            else:
                if nonempty_search_results:
                    search_interpretation = (" Our Internet search results mostly agree. "
                                             + search_interpretation
                                             )
                actions_for_dest["why"] = ("The activity for this destination shows the following. "
                                           + inference_descriptions
                                           + search_interpretation
                                           )
            activity_grouping.update_confidence_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                , actions_for_dest["confidence"]
                                                                )
            if not sus_dest_evidence["has_IP"]:
                actions_for_dest["why"] = ("We have "
                                           + actions_for_dest["confidence"]
                                           + " confidence that this site is exhibiting Malicious Activity in this sample, especially because "
                                           + noip_commentary
                                           + " "
                                           + actions_for_dest["why"]
                                           )
                relabel_destination_category(sus_name_and_port_evidence
                                             , "Malicious Activity"
                                             , actions_for_dest["why"]
                                             , actions_for_dest["confidence"]
                                             )
            else:
                category = "Suspicious Activity"
                if "actual_page_loaded" in all_inferences:
                    if 0 <= age_as_days < 7:  # 1 week old
                        category = "Malicious Activity"
                        actions_for_dest["confidence"] = "Medium"
                        if "has_autofill_form" in all_inferences:
                            actions_for_dest["confidence"] = "Medium-High"
                actions_for_dest["why"] = ("We have "
                                           + actions_for_dest["confidence"]
                                           + " confidence that this site is exhibiting "
                                           + category
                                           + " in this sample"
                                           )
                if category == "Suspicious Activity":
                    # leave in Suspicious Activity group
                    actions_for_dest["why"] += ", but we aren't confident enough to label it Malicious. "
                else:
                    # move to Malicious Activity
                    actions_for_dest["why"] += ". "
                    relabel_destination_category(sus_name_and_port_evidence
                                                 , category
                                                 , actions_for_dest["why"]
                                                 , actions_for_dest["confidence"]
                                                 )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["why"]
                                                               )
    elif 5 <= inference_score <= 9:  # TODO: Think about age information here!
        likely_new_category = "Malicious Activity"
        if (
                (nonempty_search_results and sus_dest_evidence["search_results"].score > 5)
                or (not nonempty_search_results and not nonempty_misp_results)
        ):
            if nonempty_search_results:
                logger.info("Looking for "
                             + destination
                             + " in search results, where we found the following domains:\n"
                             + str(sus_dest_evidence["search_results"].domains_mentioned_in_security_results)
                             )
                if (len(sus_dest_evidence["search_results"].domains_mentioned_in_security_results) != 0
                        and destination not in sus_dest_evidence["search_results"].domains_mentioned_in_security_results
                ):
                    logger.info("YO! These search results MIGHT be for something else, not "
                                 + destination
                                 + "!!!"
                                 )
                else:
                    if sus_dest_evidence["search_results"].total_results > 10000:
                        logger.info("YO! "
                                     + destination
                                     + " is really probably not malicious!"
                                     )
            if not sus_dest_evidence["has_IP"]:
                actions_for_dest["confidence"] = "High"
            else:
                if (not built_on_trusted
                        and
                        (
                                ("created_to_captured" not in sus_dest_evidence.keys()
                                 and "created_to_now" not in sus_dest_evidence.keys()
                                )
                                or
                                ("created_to_captured" in sus_dest_evidence.keys()
                                 and sus_dest_evidence["created_to_captured"].days >= (365 * 5)
                                )
                                or
                                ("created_to_now" in sus_dest_evidence.keys()
                                 and sus_dest_evidence["created_to_now"].days >= (365 * 5)
                                )
                        )
                ):
                    if "likely_background_behavior" in sus_name_and_port_evidence["inferences"].associated_inferences:
                        likely_new_category = "Common Activity"  # ???
                    else:
                        if nonempty_search_results and 0 < sus_dest_evidence["search_results"].total_results <= 10:
                            likely_new_category = "Common Activity"  # ???
                else:  # maybe more logic here in the future
                    if built_on_trusted and "actual_page_loaded" not in all_inferences:
                        likely_new_category = "Suspicious Activity"
                    logger.info("Capturing " + destination + " as " + likely_new_category + " for now.")
                actions_for_dest["confidence"] = "Medium-High"
            if likely_new_category == "Malicious Activity":
                if nonempty_search_results:
                    search_interpretation = (
                                " However, our Internet search results (which we've interpreted as identifying the site as a "
                                + sus_dest_evidence["search_results"].risk
                                + " "
                                + sus_dest_evidence["search_results"].category
                                + " with confidence of "
                                + str(sus_dest_evidence["search_results"].score)
                                + "/10) don't generally agree. We believe this to be true because this site is likely not something that an end user would be looking for, which skews our analysis towards believing that it may be a problem. "
                                + search_interpretation
                                )
                actions_for_dest["action"] = "labelDestination"
                actions_for_dest["text"] = ("We have "
                                            + actions_for_dest["confidence"]
                                            + " confidence that this site is exhibiting "
                                            + likely_new_category
                                            + " in this sample. "
                                            + inference_descriptions
                                            + search_interpretation
                                            + "\n"
                                            + enrich_with_temporal_data(destination
                                                                        , sus_dest_evidence
                                                                        , sus_name_and_port_evidence
                                                                        )
                                            )
            else:
                if nonempty_search_results:
                    search_interpretation = (
                                " In addition, Internet search results (which we've interpreted as identifying the site as a "
                                + sus_dest_evidence["search_results"].risk
                                + " "
                                + sus_dest_evidence["search_results"].category
                                + " with confidence of "
                                + str(sus_dest_evidence["search_results"].score)
                                + "/10) mostly agree. "
                                + search_interpretation
                                )
                actions_for_dest["text"] = ("We have "
                                            + actions_for_dest["confidence"]
                                            + " confidence that this site is exhibiting "
                                            + likely_new_category
                                            + " in this sample. "
                                            + inference_descriptions
                                            + search_interpretation
                                            + "\n"
                                            + enrich_with_temporal_data(destination
                                                                        , sus_dest_evidence
                                                                        , sus_name_and_port_evidence
                                                                        )
                                            )
            # recategorize as appropriate
            relabel_destination_category(sus_name_and_port_evidence
                                         , likely_new_category
                                         , actions_for_dest["text"]
                                         , actions_for_dest["confidence"]
                                         )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["text"]
                                                               )
        else:
            actions_for_dest[
                "why"] = "We are unsure of the purpose of this site in this sample, but we don't believe that it is Malicious."
            actions_for_dest["confidence"] = "Medium"
            activity_grouping.update_confidence_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                , actions_for_dest["confidence"]
                                                                )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["why"]
                                                               )
            # leave in Suspicious Activity group
            return True
    elif 1 <= inference_score <= 4:
        if nonempty_search_results:
            search_interpretation = (" Our Internet search results say the following. " + search_interpretation)
        actions_for_dest["confidence"] = "Medium"
        actions_for_dest["why"] = (
                "Despite our Internet search results seemingly indicating that this site is malicious, we're unsure of its purpose. "
                + enrich_with_temporal_data(destination
                                            , sus_dest_evidence
                                            , sus_name_and_port_evidence
                                            )
                + " Here is more information for you to review. The activity in this sample indicates the following. "
                + inference_descriptions
                + search_interpretation
        )
        activity_grouping.update_confidence_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                            , actions_for_dest["confidence"]
                                                            )
        activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                           , actions_for_dest["why"]
                                                           )
        # leave in Suspicious Activity group
    else:
        if nonempty_search_results and sus_dest_evidence["search_results"].score == 5:
            actions_for_dest["confidence"] = "Medium-High"
            actions_for_dest["why"] = ("We have "
                                       + actions_for_dest["confidence"]
                                       + " confidence that this site is exhibiting Common Activity in this sample. The site's activity is not interesting in this sample, though our search results seem to disagree that this is an uninteresting site. "
                                       + sus_dest_evidence["search_results"].final_text
                                       )
            relabel_destination_category(sus_name_and_port_evidence
                                         , "Common Activity"
                                         , actions_for_dest["why"]
                                         , actions_for_dest["confidence"]
                                         )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["why"]
                                                               )
        elif (
                (nonempty_search_results and sus_dest_evidence["search_results"].score > 5)
                or (not nonempty_search_results and not nonempty_misp_results)
        ):
            if inference_score == 0:
                if nonempty_search_results:
                    search_interpretation = (" Our Internet search results mostly agree. " + search_interpretation)
                actions_for_dest["confidence"] = "Medium"
                actions_for_dest["why"] = ("We have "
                                           + actions_for_dest["confidence"]
                                           + " confidence that this site is exhibiting Suspicious Activity in this sample, but we aren't confident enough to label it Malicious. The activity for this destination shows the following. "
                                           + inference_descriptions
                                           + enrich_with_closed_session_info(sus_dest_evidence)
                                           + search_interpretation
                                           )
                activity_grouping.update_confidence_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                    , actions_for_dest["confidence"]
                                                                    )
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
                # leave in Suspicious Activity group
            elif inference_score < 0:
                actions_for_dest["confidence"] = "Medium"
                if nonempty_search_results:
                    search_interpretation = (
                                ", though our search results seem to disagree that this is an uninteresting site. "
                                + search_interpretation
                                )
                else:
                    search_interpretation = "."
                actions_for_dest["why"] = ("We have "
                                           + actions_for_dest["confidence"]
                                           + " confidence that this site is exhibiting Common Activity in this sample. The site's activity is not interesting in this sample"
                                           + search_interpretation
                                           )
                relabel_destination_category(sus_name_and_port_evidence
                                             , "Common Activity"
                                             , actions_for_dest["why"]
                                             , actions_for_dest["confidence"]
                                             )
                activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                                   , actions_for_dest["why"]
                                                                   )
    return True


def determine_if_actually_benign(sus_dest_evidence, sus_name_and_port_evidence, destination, inference_object,
                                 inference_score,
                                 inference_descriptions, actions_for_dest, parent_domain_commentary, misp_purpose,
                                 initial_risk, initial_category, details_text):
    """If the interpretation of our Search results about a (currently) Suspicious Activity leads us to believe that it's
       actually benign, this function attempts to confirm or deny that verdict based on all of the other evidence
       we have collected. The end goal will be to recategorize each site (when appropriate) and update why we believe
       that the recategorization is correct. Note that all cases should stop our analysis from going any farther for
       this site, which is captured by returning True.
    """

    if inference_score >= 5:
        if (
                (sus_dest_evidence["search_results"] is not None and sus_dest_evidence["search_results"].score > 2)
                or misp_purpose == "Semi-Popular Site"
        ):
            if "likely_c2" in inference_object.associated_inferences:
                new_category = "Common Activity"
                actions_for_dest["confidence"] = "Medium"
                actions_for_dest["why"] = ("We have "
                                           + actions_for_dest["confidence"]
                                           + " confidence that this site is Common Activity in this sample, perhaps performing analytics or non-malicious tracking/reporting. "
                                           + inference_descriptions
                                           + " Our OSINT analysis"
                                           + parent_domain_commentary
                                           + ", which we've interpreted as identifying the site as a "
                                           + initial_risk
                                           + " "
                                           + initial_category
                                           + ", mostly agrees. Additional details are as follows. "
                                           + details_text
                                           )
            else:
                new_category = "Attack Vector"
                actions_for_dest["confidence"] = "Medium"
                actions_for_dest["why"] = ("We have "
                                           + actions_for_dest["confidence"]
                                           + " confidence that this site is acting as an Attack Vector in this sample. "
                                           + inference_descriptions
                                           + " Our OSINT analysis"
                                           + parent_domain_commentary
                                           + ", which we've interpreted as identifying the site as a "
                                           + initial_risk
                                           + " "
                                           + initial_category
                                           + ", mostly agrees. Additional details are as follows. "
                                           + details_text
                                           + "\nIf there is Malicious or Suspicious activity in this sample, this site may be the way that behavior was hosted and served to the user."
                                           )
            relabel_destination_category(sus_name_and_port_evidence
                                         , new_category
                                         , actions_for_dest["why"]
                                         , actions_for_dest["confidence"]
                                         )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["why"]
                                                               )
        else:
            actions_for_dest["confidence"] = "Medium-High"
            actions_for_dest["why"] = ("We have "
                                       + actions_for_dest["confidence"]
                                       + " confidence that this site is acting as Common Activity in this sample. "
                                       + inference_descriptions
                                       + " Our OSINT analysis"
                                       + parent_domain_commentary
                                       + ", which we've interpreted as identifying the site as a "
                                       + initial_risk
                                       + " "
                                       + initial_category
                                       + ", mostly agrees. Additional details are as follows. "
                                       + details_text
                                       + "\n"
                                       + enrich_with_temporal_data(destination
                                                                   , sus_dest_evidence
                                                                   , sus_name_and_port_evidence
                                                                   )
                                       )
            relabel_destination_category(sus_name_and_port_evidence
                                         , "Common Activity"
                                         , actions_for_dest["why"]
                                         , actions_for_dest["confidence"]
                                         )
            activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                               , actions_for_dest["why"]
                                                               )
    elif 1 <= inference_score <= 4:
        actions_for_dest["confidence"] = "Medium-High"
        actions_for_dest["why"] = ("We have "
                                   + actions_for_dest["confidence"]
                                   + " confidence that this site is acting as Common Activity in this sample. "
                                   + inference_descriptions
                                   + " Our OSINT analysis"
                                   + parent_domain_commentary
                                   + ", which we've interpreted as identifying the site as a "
                                   + initial_risk
                                   + " "
                                   + initial_category
                                   + ", mostly agrees. Additional details are as follows. "
                                   + details_text
                                   + "\n"
                                   + enrich_with_temporal_data(destination
                                                               , sus_dest_evidence
                                                               , sus_name_and_port_evidence
                                                               )
                                   )
        relabel_destination_category(sus_name_and_port_evidence
                                     , "Common Activity"
                                     , actions_for_dest["why"]
                                     , actions_for_dest["confidence"]
                                     )
        activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                           , actions_for_dest["why"]
                                                           )
    else:  # 0 or lower inference score
        actions_for_dest["confidence"] = "High"
        actions_for_dest["why"] = ("We have "
                                   + actions_for_dest["confidence"]
                                   + " confidence that this site is acting as Common Activity in this sample. There is no evidence of this site doing anything interesting in this sample. "
                                   + inference_descriptions
                                   + " Our OSINT analysis"
                                   + parent_domain_commentary
                                   + ", which we've interpreted as identifying the site as a "
                                   + initial_risk
                                   + " "
                                   + initial_category
                                   + ", agrees. Additional details are as follows. "
                                   + details_text
                                   + "\n"
                                   + enrich_with_temporal_data(destination
                                                               , sus_dest_evidence
                                                               , sus_name_and_port_evidence
                                                               )
                                   )
        relabel_destination_category(sus_name_and_port_evidence
                                     , "Common Activity"
                                     , actions_for_dest["why"]
                                     , actions_for_dest["confidence"]
                                     )
        activity_grouping.save_description_for_destination(sus_name_and_port_evidence["activity_groups"]
                                                           , actions_for_dest["why"]
                                                           )
    return True


def analyze_whois_data(whois_data, verdict_collector_dict, sample_metadata):
    """WHOIS data is a useful source of knowledge to determine age of a domain, how it was registered, and where it was
        registered. This function collects some of the valuable aspects from here for us to analyze later.
    """
    high_trust_registrars = ["MarkMonitor, Inc."]

    if whois_data is not None:
        if "registrar" not in whois_data.keys():
            logger.info("WHOIS data is missing registrar, so we're not capturing it.")
            return
        if whois_data["registrar"] in high_trust_registrars:
            verdict_collector_dict["high_trust_registrar"] = True
        if "domain_name" in whois_data.keys():
            try:
                if type(whois_data["domain_name"]) == list:
                    root_domain_by_whois = whois_data["domain_name"][0].lower()
                else:
                    root_domain_by_whois = whois_data["domain_name"].lower()
                if root_domain_by_whois is not None:
                    verdict_collector_dict["root_domain_by_whois"] = root_domain_by_whois
                else:
                    logger.info("got Nonetype for WHOIS root domain name. Not collecting.")
            except:
                logger.info("Something went wrong collecting WHOIS root domain name.")
        try:
            if "name_servers" in whois_data.keys():
                if ("blockedduetophishing.pleasecontactsupport.com" in whois_data["name_servers"]
                        or "blockedduetophishing.pleasecontactsupport.com" == whois_data["name_servers"]
                ):
                    verdict_collector_dict["phishing_by_whois"] = True
                    logger.info("WHOIS provider has already identified this site as a known phishing site!")
        except:
            logger.info("Didn't find WHOIS nameserver information")
        try:
            if type(whois_data["updated_date"]) == list:
                updated = whois_data["updated_date"][0]
            else:
                updated = whois_data["updated_date"]
        except:
            logger.info("Something went wrong parsing WHOIS updated date")
        try:
            if type(whois_data["creation_date"]) == list:
                created = whois_data["creation_date"][0]
            else:
                created = whois_data["creation_date"]
        except:
            logger.info("Something went wrong parsing creation date")
        now = datetime.datetime.today()
        try:
            captured = datetime.datetime.fromtimestamp(float(sample_metadata["traffic_date"]))
            verdict_collector_dict["created_to_captured"] = captured - created
        except:
            pass
        try:
            verdict_collector_dict["created_to_updated"] = updated - created
        except:
            pass
        try:
            verdict_collector_dict["created_to_now"] = now - created
        except:
            pass
        try:
            verdict_collector_dict["updated_to_now"] = now - updated
        except:
            pass
        try:
            if "created_to_captured" in verdict_collector_dict.keys():
                # capture date of traffic is more correct than "now", though in realtime cases it should be similar
                relevant_datetime = verdict_collector_dict["created_to_captured"]
            else:
                relevant_datetime = verdict_collector_dict["created_to_now"]
            if relevant_datetime.days == 0:
                verdict_collector_dict["reason_text"].add("this destination was created within the last day.")
            elif relevant_datetime.days < 7:
                verdict_collector_dict["reason_text"].add("this destination was created within the last week.")
            elif relevant_datetime.days < 30:
                verdict_collector_dict["reason_text"].add("this destination was created within the last month.")
            elif relevant_datetime.days < 365:
                verdict_collector_dict["reason_text"].add("this destination was created within the last year.")
            elif relevant_datetime.days >= 1460:  # 4 years
                verdict_collector_dict["reason_text"].add("this destination was created at least 4 years ago.")
        except:
            logger.info("Couldn't collect useful time difference information")
        try:
            verdict_collector_dict["nameservers"] = whois_data["name_servers"]
        except:
            logger.info("Didn't find nameserver information")
        try:
            verdict_collector_dict["org_by_whois"] = whois_data["org"]
        except:
            logger.info("Didn't find WHOIS org information")


def analyze_unknown_destination_flow_data(flow_data, verdict_collector_dict):
    """Unknown destinations are destinations where we have no metadata (such as Destinations, Behaviors, and Events) to
        associate with it. It is important to avoid showing a user a bunch of unknown stuff that isn't actually
        interesting from a security perspective. This function begins to try to capture whether there are or are not
        things of note (based on flow categories observed in the given sample) for a given unknown destination.
    """
    verdict_collector_dict["total_flows_in_sample"] = len(flow_data)
    verdict_collector_dict["max_commonality"] = max(f["global_count"] for f in flow_data)
    unique_flow_categories = set()
    for f in flow_data:
        unique_flow_categories.add(f["flow_category"])

    if "failedConnection" in unique_flow_categories and len(unique_flow_categories) == 1:
        verdict_collector_dict["has_failed_connection_only"] = True
    elif "closedSession" in unique_flow_categories and len(unique_flow_categories) == 1:
        verdict_collector_dict["has_closed_session_only"] = True
    for cat in unique_flow_categories:
        category = cat.lower()
        if "download" in category:
            verdict_collector_dict["has_download"] = True
        if "upload" in category:
            verdict_collector_dict["has_upload"] = True
        if "unclassified" in category:
            verdict_collector_dict["has_unclassified"] = True
        if "major" in category:
            verdict_collector_dict["has_major_download"] = True
        if "largeupload" in category:
            verdict_collector_dict["has_major_upload"] = True
        if "major" in category:
            verdict_collector_dict["has_major_download"] = True
        if "some" in category:
            verdict_collector_dict["has_meaningful_download"] = True
        if cat in ["asNeededChannel", "unidirectional", "unclassified", "singleResourceLoaded"]:
            verdict_collector_dict["common_c2_categories"] = True


def analyze_known_activities(known_activities, verdict_dict):
    """Known activities are for activities in this sample where we have additional metadata about the destination.
        This is a list of dicts, where each entry contains the following for a given destination:
        + secflow -> a dict containing all secflow attributes
        + destination -> a dict containing all destination attributes
        + behavior -> a dict containing all behavior attributes
        + flowIdCount -> an integer identifying how many samples this
                         particular flowCategory for this destination exists in
       Any of the dicts can be empty, which means that we don't have info on that secflow for that layer of enrichment.
       The goal here is to help us better use this known information about destinations in later steps.
    """
    metadata_levels = ["event", "behavior", "destination"]

    for entry in known_activities:
        dest = entry["secflow"]["destinationData"]
        if dest not in verdict_dict.keys():
            verdict_dict[dest] = dict()
            verdict_dict[dest]["reason_text"] = set()
        for level in metadata_levels:
            if level not in entry.keys():
                continue
            if len(entry[level]) > 0 and type(entry[level]) == dict:
                if "securityTags" in entry[level].keys():
                    try:
                        tags = ast.literal_eval(entry[level]["securityTags"])
                    except:
                        tags = []
                    if "Captcha" in tags:
                        verdict_dict["sample_attributes"]["has_captcha"] = True
                        verdict_dict[dest]["reason_text"].add(
                            "This is a known Captcha site. This means that if this was generated via automated analysis, you may not have seen all of the relevant activity. Ideally, you should provide the original network flows or perform a manual sandbox analysis.")
                    elif "Authentication" in tags:
                        verdict_dict["sample_attributes"]["has_authentication"] = True
                        verdict_dict[dest]["reason_text"].add(
                            "This is known to be related to authentication. This means that if this was generated via automated analysis, you may not have seen all of the relevant activity. Ideally, you should provide the original network flows or perform a manual sandbox analysis.")
                if "attackVectorTags" in entry[level].keys():
                    try:
                        tags = ast.literal_eval(entry[level]["attackVectorTags"])
                    except:
                        tags = []
                    if "FileSharingPlatform" in tags:
                        verdict_dict["sample_attributes"]["has_fileSharingPlatform"] = True
                if "destinationTags" in entry[level].keys():
                    try:
                        tags = ast.literal_eval(entry[level]["destinationTags"])
                    except:
                        tags = []
                    if "FileSharingPlatform" in tags:
                        verdict_dict["sample_attributes"]["has_fileSharingPlatform"] = True
                if "threatTags" in entry[level].keys():
                    try:
                        tags = ast.literal_eval(entry[level]["threatTags"])
                    except:
                        tags = []
                    if "Phishing" in tags:
                        verdict_dict["sample_attributes"]["has_phishing"] = True
                        verdict_dict[dest]["reason_text"].add("This is a known phishing site!")
        if len(entry["destination"]) == 0 and len(entry["behavior"]) == 0:
            logger.info("Error: "
                         + dest
                         + " shouldn't have been identified as a known activity. Skipping."
                         )
            continue
    logger.info("Known destination analysis complete. Results: "
                 + str(verdict_dict.items())
                 )


def relabel_destination_category(destination_info, final_category, why, confidence):
    """In the process of analyzing all of the data that we have access to, it's likely that we will originally have
        a destination in one category (most commonly "Suspicious Activity") that actually belongs elsewhere (such as
        "Attack Vector", "Common Activity", etc...). This function handles taking the destination information (which
        contains its initial category) and relocating it to the right category. It also captures why we did that.
    """
    # grab the destination's categorization from inference object
    if "inferences" not in destination_info.keys():
        logger.info("ERROR, no inference object found for destination.")
        return False
    if "activity_groups" not in destination_info.keys():
        logger.info("ERROR, no activity groups found for destination.")
        return False
    inference_object = destination_info["inferences"]
    inference_object.category = final_category

    # rewrite all activity groups
    activity_grouping.relabel_category_for_destination(destination_info["activity_groups"]
                                                       , final_category
                                                       , confidence
                                                       )
    return True


def get_all_groups_by_category(category, evidence):
    """Takes a category to be looked up and all evidence (which includes all destinations), and returns a list of tuples
        where each tuple has the format (destination name, [ordered activity groups]). The activity groups are ordered
        by min start time of the group.
    """
    groups_by_destination = []
    for destination in evidence.destination_data.keys():
        dest_evidence = evidence.destination_data[destination]
        groups = []
        for dest_and_port_record in dest_evidence["full_destinations"]:
            if "activity_groups" in dest_and_port_record.keys():
                for group in dest_and_port_record["activity_groups"]:
                    if group.category == category:
                        groups += [group]
        if groups != []:
            groups_by_destination += [(destination
                                       , groups
                                       )
                                      ]
    return groups_by_destination


def get_most_severe_category(destination_cat_records, dest_evidence):
    """Provide the final categorization and confidence level for a particular destination, based on the "worst"
        categorization and confidence of all of its fqdn:port "children."
    """
    quantitative_categories = {5: [],
                               4: [],
                               3: [],
                               2: [],
                               1: [],
                               0: []
                               }
    for record in destination_cat_records:
        category = record[0]
        confidence = record[1]
        dest_and_port = record[2]
        if category == "Impact":
            quantitative_categories[5].append((confidence, dest_and_port))
        elif category == "Malicious Activity":
            quantitative_categories[4].append((confidence, dest_and_port))
        elif category == "Suspicious Activity":
            quantitative_categories[3].append((confidence, dest_and_port))
        elif category == "Attack Vector":
            quantitative_categories[2].append((confidence, dest_and_port))
        elif category == "Common Activity":
            quantitative_categories[1].append((confidence, dest_and_port))
        else:
            quantitative_categories[0].append((confidence, dest_and_port))
    most_severe_category = "Suspicious Activity"  # defaults
    confidence = "Medium"
    max_cat = 0
    for cat in quantitative_categories.keys():
        if len(quantitative_categories[cat]) == 0:
            continue
        max_cat = max(max_cat, cat)
    if max_cat == 5:
        most_severe_category = "Impact"
    elif max_cat == 4:
        most_severe_category = "Malicious Activity"
    elif max_cat == 3:
        most_severe_category = "Suspicious Activity"
    elif max_cat == 2:
        most_severe_category = "Attack Vector"
    elif max_cat == 1:
        most_severe_category = "Common Activity"
    for record in quantitative_categories[max_cat]:
        if "High" in record[0]:
            confidence = "High"
            dest_and_port = record[1]
        elif "Medium-High" in record[0]:
            confidence = "Medium-High"
            dest_and_port = record[1]
        elif "Medium" in record[0]:
            confidence = "Medium"
            dest_and_port = record[1]
        elif "Medium-Low" in record[0]:
            confidence = "Medium-Low"
            dest_and_port = record[1]
        elif "Low" in record[0]:
            confidence = "Low"
            dest_and_port = record[1]
        else:
            logger.info(
                "While trying to assign final categorization, we couldn't find useful data. Setting to Medium confidence Suspicious.")
    """If there is more than one category associated with the dest_and_port entries of a destination, assign them all 
        to most severe category.
    """
    if len(destination_cat_records) > 1:
        dest_and_port_evidence = None
        for record in destination_cat_records:
            record_category = record[0]
            record_confidence = record[1]
            record_dest_and_port = record[2]
            if record_category != most_severe_category:
                for dest_and_port_record in dest_evidence["full_destinations"]:
                    if dest_and_port_record["name_and_port"] == record_dest_and_port:
                        dest_and_port_evidence = dest_and_port_record
                        break
                if dest_and_port_evidence is not None:
                    relabel_destination_category(dest_and_port_evidence,
                                                 most_severe_category,
                                                 [],
                                                 confidence
                                                 )
                else:
                    logger.info("While trying to relabel destination category we weren't able to find a record.")
    return most_severe_category, confidence


def get_by_category(category, evidence):
    """Takes a category to be looked up and all evidence (which includes all destinations), and returns a dictionary of
        groups of destinations that had that category at the beginning (the "known") vs. those that received that
        category after analysis of evidence (the "inferred").
    """
    final_data = {
        "known": set(),
        "known_fqdns": set(),
        "inferred": set(),
        "inferred_fqdns": set()
    }
    for destination in evidence.destination_data.keys():
        dest_evidence = evidence.destination_data[destination]
        destination_categories = []
        for dest_and_port_record in dest_evidence["full_destinations"]:
            if "activity_groups" in dest_and_port_record.keys():
                for group in dest_and_port_record["activity_groups"]:
                    destination_categories += [(group.category, group.confidence, group.destination_and_port)]
                    break  # only collect one from each full destination, since they should be identical
        my_category, confidence = get_most_severe_category(destination_categories, dest_evidence)
        for dest_and_port_record in dest_evidence["full_destinations"]:
            if my_category == category:
                if category == "Suspicious Activity":
                    final_data["inferred"].add(
                        (dest_and_port_record["name_and_port"],
                         confidence
                         )
                    )
                    final_data["inferred_fqdns"].add(
                        (destination,
                         confidence
                         )
                    )
                    continue
                if category == dest_evidence["initial_category"]:
                    final_data["known"].add(
                        (dest_and_port_record["name_and_port"],
                         confidence
                         )
                    )
                    final_data["known_fqdns"].add(
                        (destination,
                         confidence
                         )
                    )
                else:
                    final_data["inferred"].add(
                        (dest_and_port_record["name_and_port"],
                         confidence
                         )
                    )
                    final_data["inferred_fqdns"].add(
                        (destination,
                         confidence
                         )
                    )
    return final_data


def get_age_tuple(sus_dest_evidence):
    """Using either the created to captured date or the created to now date (defaulting to the former when we have it),
        return a tuple of the relevant datetime field we've used and the age of the domain.
    """
    datetime_data = None
    age_as_days = -1
    if "created_to_captured" in sus_dest_evidence.keys():
        age_as_days = sus_dest_evidence["created_to_captured"].days
        datetime_data = sus_dest_evidence["created_to_captured"]
    elif "created_to_now" in sus_dest_evidence.keys():
        age_as_days = sus_dest_evidence["created_to_now"].days
        datetime_data = sus_dest_evidence["created_to_now"]

    return (datetime_data, age_as_days)


def enrich_with_temporal_data(destination_name, sus_dest_evidence, sus_name_and_port_evidence):
    """Time-sensitive information that helps to raise or lower the score and category of some destination that we've
        already begun classifying.
    """
    additional_info = ""
    if "phishing_by_whois" in sus_dest_evidence.keys():
        additional_info += " This site has been reported to its registrar as a known phishing site. "
    if "inferences" in sus_name_and_port_evidence.keys():
        inference_object = sus_name_and_port_evidence["inferences"]
    else:
        return additional_info  # nothing to do, really
    if "built_on_trusted" not in inference_object.associated_inferences.keys():
        (relevant_datetime, age_as_days) = get_age_tuple(sus_dest_evidence)
        if relevant_datetime is None or utilities.get_destination_type(destination_name) == "IP":
            return additional_info
        age_string = utilities.pretty_print_domain_age(relevant_datetime)
        additional_info = "This site was" + age_string + "."
    if not sus_dest_evidence["has_IP"]:
        additional_info += " At this point, it doesn't resolve to an IP address, which is extremely suspicious. Sites that are not threats generally don't lose their IP addresses."
        return additional_info
    if "built_on_trusted" not in inference_object.associated_inferences.keys():
        if age_as_days < 14:
            additional_info += " Common reasons for seeing activity to very new sites include an attack (such as phishing), a site related to the debut of something new (a movie, a service, a business), use of a VPN (which constantly use new domains to bypass blocklists), or analytics/tracking sites (for similar reasons to VPNs)."
        elif age_as_days < 365:
            additional_info += " There are many sites that fall into this age range. Focusing on the activity surrounding this site (especially if there are known Attack Vectors or Impacts) is likely the best way to understand if it is interesting if other information provided does not help to clarify its role."
        elif age_as_days >= 730:
            additional_info += " While there are attackers who explicitly age their domains to avoid detection, the majority of older domains are uninteresting (from a security perspective). If this site seems to have just become active recently, is near highly suspicious activity (such as login portals or known Impacts), or other information provided points to its maliciousness, then it could be something to dig deeper into. However, if not, it may simply be background infrastructure for a site."
    return additional_info


def determine_next_steps(verdict_collector_dict, evidence, proposed_actions_dict, categorized_activity_data, client,
                         osint_source=None):
    """Using the information we've learned for this Sample, determine what steps we should take next. Not currently
        meant for consumption in production.
    """
    msg = ""

    sample_attributes = dict()
    if "sample_attributes" in verdict_collector_dict.keys():
        sample_attributes = verdict_collector_dict["sample_attributes"]
    if osint_source is not None and len(sample_attributes) > 0:
        sample_attributes["has_osint"] = True

    if "overall_recommendations" not in proposed_actions_dict.keys():
        proposed_actions_dict["overall_recommendations"] = {"text": ""
            , "action": None
                                                            }
    potential_actions = set()
    for dest in proposed_actions_dict:
        potential_actions.add(proposed_actions_dict[dest]["action"])

    if "labelDestination" in potential_actions:
        proposed_actions_dict["overall_recommendations"]["action"] = "tweet"
    elif "submitToManualSandbox" in potential_actions:
        proposed_actions_dict["overall_recommendations"]["action"] = "submitToManualSandbox"
    if "has_captcha" in sample_attributes:
        proposed_actions_dict["overall_recommendations"][
            "text"] += "There is a captcha present in this sample, which means that malicious activity may have been prevented from appearing. "
        proposed_actions_dict["overall_recommendations"]["action"] = "submitToManualSandbox"
    if "has_authentication" in sample_attributes:
        proposed_actions_dict["overall_recommendations"][
            "text"] += "There is activity that suggests authentication may have been a goal in this sample (such as a login portal loading). "
        proposed_actions_dict["overall_recommendations"]["action"] = "submitToManualSandbox"
    if "has_phishing" in sample_attributes:
        proposed_actions_dict["overall_recommendations"][
            "text"] += "There is a known phishing site in this sample. Sharing this relationship with the infosec community will likely be beneficial. "
        proposed_actions_dict["overall_recommendations"][
            "action"] = "tweet"  # share with Twitter, since we've found relationships that may not have been previously known
    if "has_fileSharingPlatform" in sample_attributes:
        proposed_actions_dict["overall_recommendations"][
            "text"] += "There is activity in this sample that leverages a known file-sharing platform. This platform may have been used to load a site, download a file, or communicate with an attacker. If it looks like the sample has been stopped short of doing interesting activity, we recommend analyzing in our semi-manual sandbox. "
        proposed_actions_dict["overall_recommendations"]["action"] = "submitToManualSandbox"

    if "has_osint" not in sample_attributes:
        cancel_submission_recommendation = True
        for destination in proposed_actions_dict.keys():
            if destination == "overall_recommendations":
                continue
            else:
                if actions_for_dest["action"] == "labelDestination":
                    cancel_submission_recommendation = False
                    break
        if cancel_submission_recommendation:
            proposed_actions_dict["overall_recommendations"]["text"] = ""
            proposed_actions_dict["overall_recommendations"]["action"] = None

    if len(evidence.destination_data) > 10:
        if (
                ("Impact" in categorized_activity_data.keys() and len(categorized_activity_data["Impact"]) > 0)
                or ("Malicious Activity" in categorized_activity_data.keys() and len(
            categorized_activity_data["Malicious Activity"]) > 0)
        ):
            msg = "This definitely seems to have some useful things to share, so we recommend retweeting. We'll prepare that for you; one moment."
        elif ("Suspicious Activity" in categorized_activity_data.keys()
              and len(categorized_activity_data["Suspicious Activity"]) > 0
        ):
            if "action" in proposed_actions_dict["overall_recommendations"].keys():
                if proposed_actions_dict["overall_recommendations"]["action"] == "tweet":
                    msg = "This definitely seems to have some useful things to share, so we recommend retweeting. We'll prepare that for you; one moment."
                elif proposed_actions_dict["overall_recommendations"]["action"] == "submitToManualSandbox":
                    msg = (proposed_actions_dict["overall_recommendations"]["text"]
                           + " You can do that in Slack by typing:\n`/sandbox-manual fullAnalysis <url of interest>`."
                           )
    if msg == "":
        msg = "There doesn't seem to be anything terribly useful in here, so we don't suggest that this data is worth sharing via Tweet."
    slack.send_thread_reply(evidence.other_metadata["channel_id"]
                            , msg
                            , evidence.other_metadata["msg_id"]
                            )


def get_sample_duration(evidence):
    """Helper function to grab full duration of a sample. Return value will be a float.
    """
    if "activity_groups" not in evidence.sample_metadata.keys():
        return 0.0
    latest = 0.0
    for activity_group in evidence.sample_metadata["activity_groups"]:
        latest = max(latest, activity_group.last_seen_in_this_group)
    return latest


def collect_sandbox_evidence(is_fresh, mode, candidate_link, candidate_result_data, via_slack, evidence, channel=None,
                             thread=None):
    """Not used in code meant for production!!!!
    Takes a candidate link/destination that we think may have a category defined in the candidate_result_data dict
    (contains category, confidence, etc...). Based on the information we already know about the candidate, subject it to
    appropriate tests to collect more evidence.
    """
    sandbox_servername = ""
    if mode == "automated":
        api_key = authentication.get_api_key_for_account("modified@seclarity.io")
    elif mode == "manual":
        api_key = authentication.get_api_key_for_account("modified@seclarity.io")
    else:
        logger.info("Unrecognized mode " + mode)
        return None
    is_public = False
    sample_info = dict()

    if is_fresh:  # this is a fresh sample that we should analyze in one of our sandboxes
        sandbox_analysis_results = sandbox.call_sandbox(mode
                                                        , sandbox_servername
                                                        , candidate_link
                                                        , upload_choice=True
                                                        , user_response_required=False
                                                        )
        if sandbox_analysis_results is None:
            msg = ("Something failed while trying to start "
                   + mode
                   + " sandbox."
                   )
            if via_slack:

                slack.send_thread_reply(channel, msg, thread)
            else:
                logger.info(msg)
        else:
            sample_info = sandbox.handle_sandbox_result(sandbox_analysis_results
                                                        , api_key
                                                        , sandbox_servername
                                                        )  # upload actually happens here
            if sample_info is None:
                msg = "Some unknown error occurred while uploading file. Analysis will not continue."
                if via_slack:
                    slack.send_thread_reply(channel, msg, thread)
                else:
                    logger.info(msg)
                return None
            elif sample_info["error"]:
                should_quit = False
                if sample_info["body"].endswith("403"):
                    msg = "Request was unauthorized. This means that your API key may no longer be valid. Exiting."
                    should_quit = True
                else:
                    msg = response["body"]
                if via_slack:

                    slack.send_thread_reply(channel, msg, thread)
                else:
                    logger.info(msg)
                if should_quit:
                    sys.exit(1)
                return None
    else:  # just a test result, or something we're reviewing after the fact
        logger.info("Test result analysis starting...")
        is_public = True
        sample_info[
            "uuid"] = ""
        sample_info["fileName"] = ""
    if len(sample_info) > 0:
        link = utilities.generate_sample_link_from_uuid(sample_info["uuid"])
        if link is None:
            logger.info("Couldn't find link for sample. Sample info returned: " + str(sample_info.items()))
            return link  # something went wrong
        evidence.sample_metadata["uuid"] = sample_info["uuid"]
        msg = (mode.capitalize()
               + " sample creation successful. Beginning to automatically collect additional evidence. To view the automated sample, click <"
               + link
               + "|here>: "
               )
        if via_slack:

            slack.send_thread_reply(channel, msg, thread)
        else:
            logger.info(msg)
    else:
        msg = "Error creating sample. Quitting."
        if via_slack:

            slack.send_thread_reply(channel, msg, thread)
        else:
            logger.info(msg)
        return None

    if mode == "manual":
        """ For results that have a successful manual sandbox run, we should
            analyze the sandbox MITM file to understand anything about the destinations, including which may be a credential stealer, attack vectors, etc...
        """
        path_info = ""
        # TODO: Need to make path less terrible, or auto-find it
        analyzed_manual_sandbox_results = sandbox.analyze_http_behavior(path_info
                                                                        + sample_info["fileName"][:-4]
                                                                        + "mitm"
                                                                        )
    else:  # automated sandbox analysis
        path_info = ""
        analyzed_manual_sandbox_results = None

    # When we get the link, gather all NetworkSage metadata so we can leverage it for later analysis.
    retrieve_metadata.gather_sample_metadata(evidence
                                             , api_key
                                             , analyzed_manual_sandbox_results
                                             , path_info
                                             )
    return evidence


def analyze_from_initial_osint(osint_data, verdict_collector_dict):
    """Not used in production.
        Gets information from some incoming OSINT (such as knowledge from a user in a tweet).
    """
    if osint_data is not None:
        verdict_collector_dict["title"] = "Known " + osint_data["category"].capitalize() + " Site"
    # TODO: Get name from Twitter user and/or other sources


def analyze_from_manual_sandbox(manual_sandbox_data, verdict_collector_dict):
    """Not used in production.
        Analyzes data we found from inspecting our manual sandbox results (which can contain information about
        credentials that were typed, etc...) to include in our verdict.
    """
    if manual_sandbox_data is not None:
        general_data = manual_sandbox_data[0]
        reason = ("observed an HTTP "
                  + general_data["method"]
                  + " to URI "
                  + general_data["uri"]
                  + " where the body contained known credentials."
                  )
        verdict_collector_dict["reason_text"].add(reason)
        verdict_collector_dict["credential_collection"] = True


def interpret_misp_warninglist_data(destination, warninglist_results):
    """This takes the raw MISP warninglist data that we've collected for a given domain and tries to interpret the
        information learned from it to determine which activity category the destination belongs in, as well as any
        more specific information (such as its purpose). Note that at some point, this may be stuff that we want to
        directly pull into the platform (possibly automatically as we find it here).
    """
    url_shortener_terms = re.compile(r"(^| )(url|link) shorten", flags=re.IGNORECASE)
    tld_terms = re.compile(r"(^| )TLDs($| )")
    ddns_terms = re.compile(r"known dynamic DNS domains")
    business_terms = re.compile(r"known (bank)", flags=re.IGNORECASE)
    crl_ocsp_terms = re.compile(r"(^| )(CRL|OCSP) ")
    top_x_terms = re.compile(
        r"^(Top [1-9]{1}((K{0,1})(0{0,1})( {0,1})(0{0,3}))?K{0,1}) ")  # get top matches, but avoid top 1,000,000
    o365_ip_terms = re.compile(r"known Office 365 IP", flags=re.IGNORECASE)
    azure_datacenter_terms = re.compile(r"known Microsoft Azure Datacenter IP", flags=re.IGNORECASE)
    ip_discovery_terms = re.compile(r"\'what\'s my ip\'", flags=re.IGNORECASE)  # use on description
    category = None
    purpose = None
    if warninglist_results is not None:
        for warninglist_match in warninglist_results:
            name = warninglist_match.name
            if warninglist_match.name.startswith("List of ") and len(warninglist_match.name) > 8:
                name = warninglist_match.name[8:]
            description = warninglist_match.description
            if re.findall(url_shortener_terms, name):
                category = "Attack Vector"
                purpose = "URL Shortener"
            elif re.findall(tld_terms, name) or re.findall(ddns_terms, name):
                category = "Attack Vector"
                purpose = "Cloud-Hosting Platform"
            elif re.findall(ip_discovery_terms, description):
                category = "Common Activity"
                purpose = "IP Address Discovery"
            elif re.findall(crl_ocsp_terms, name):
                category = "Common Activity"
                purpose = "Certificate Validation"
            elif re.findall(business_terms, name):
                category = "Common Activity"
                purpose = "Known Business Site"
            elif re.findall(top_x_terms, name):
                category = "Common Activity"
                purpose = "Semi-Popular Site"
            elif re.findall(o365_ip_terms, name):
                category = "Common Activity"
                purpose = "Microsoft Office 365 IP address"
            elif re.findall(o365_ip_terms, name):
                category = "Common Activity"
                purpose = "Microsoft Azure Datacenter IP address"
    return category, purpose
