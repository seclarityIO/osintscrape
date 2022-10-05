"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import logging

import evidence_collector
from activitygroup import activity_grouping
from analysis import analysis
from inferences import inference_analysis
from metadatascripts import retrieve_metadata

logger = logging.getLogger("Display")

"""This module is where the proposed user-facing APIs (and many of their supporting functions) exist. They perform all
    analysis and attempt to provide the user with the appropriate level of information (as precise and concise as
    possible in the case of the summary, and as complete and precise as possible in the case of the activity grouping).
"""


def get_destination_summary(destination, incoming_evidence=None, apikey=None, via_slack=False):
    """This call is meant to be an API endpoint exposed to the user as follows:
            https://api.seclarity.io/sec/v1.0/destinaitons/"+destination+"/summary
        When a destination is known, it returns the information currently captured in our destination API lookup, with
        the addition of a "known" flag set to True. When a destination is not known, it returns the "known" flag set to
        False and provides the following information (JSON-formatted) for the destination:
            + known
            + verdict
            + confidence
            + summary (attempt of writing a coherent and concise description for the user)
    """
    unknowns = []
    knowns = []
    summary_data = dict()
    all_activities = []  # we won't have activities in this scenario
    evidence = evidence_collector.EvidenceCollector()
    evidence = evidence.collect_evidence(incoming_evidence
                                         , apikey
                                         , via_slack
                                         )
    db_results = retrieve_metadata.get_metadata_for_item("destination", destination, apikey)
    if len(db_results) == 0:
        unknowns = [destination]
    else:
        knowns = [destination]
    (knowns, unknowns) = retrieve_metadata.discover_partially_known(unknowns
                                                                    , knowns
                                                                    , all_activities
                                                                    , apikey
                                                                    )
    if len(knowns) > 0:
        summary_data["known"] = True
        summary_data[destination] = db_results
    else:
        # We don't have any activities, so these are necessarily empty
        labeled_activities = []
        buckets = []
        activity_groups = []
        all_inference_objects = inference_analysis.collect_inferences(labeled_activities
                                                                      , buckets
                                                                      , activity_groups
                                                                      , knowns
                                                                      , apikey
                                                                      , unknowns
                                                                      )
        evidence.sample_metadata["activity_groups"] = activity_groups
        evidence.sample_metadata["inferences"] = all_inference_objects
        retrieve_metadata.collect_activity_info_about_destinations(evidence
                                                                   , unknowns
                                                                   , activity_dict=None
                                                                   , is_known=False
                                                                   , analyzed_manual_sandbox_results=None
                                                                   , path_to_sandbox_data=None
                                                                   )
        verdict = analysis.analyze_all_evidence(evidence
                                                , via_slack
                                                )
        proposed_actions_dict = analysis.semifinalize_categorization_of_suspicious_activity(verdict)
        summary_data["known"] = False
        for destination in proposed_actions_dict.keys():
            try:
                full_name = proposed_actions_dict[destination]["raw_evidence"]["destination_name"]
            except:
                full_name = destination
            try:
                category = retrieve_metadata.get_most_severe_category(proposed_actions_dict[destination][
                                                                          "raw_evidence"]["full_destinations"]
                                                                      )
            except:
                logger.info("Couldn't get category from Inferences for "
                             + destination
                             + ". Assigning to Suspicious Activity."
                             )
                category = "Suspicious Activity"
            try:
                if len(proposed_actions_dict[destination]["text"]) == 0 and "why" in proposed_actions_dict[
                    destination].keys():
                    summary_data[full_name] = {"category": category
                        , "confidence": proposed_actions_dict[destination]["confidence"]
                        , "details": proposed_actions_dict[destination]["why"]
                                               }
                else:
                    summary_data[full_name] = {"category": category
                        , "confidence": proposed_actions_dict[destination]["confidence"]
                        , "details": proposed_actions_dict[destination]["text"]
                                               }
            except:
                summary_data[full_name] = {"category": category
                    , "confidence": "Low"
                    , "details": "Something went wrong while attempting to fetch information for this destination."
                                           }
    return summary_data


def get_sample_summary(sample_id=None, incoming_evidence=None, apikey=None, via_slack=False):
    """This call is meant to be an API endpoint exposed to the user as follows:
            https://api.seclarity.io/sec/v1.0/samples/"+uuid+"/summary (proposed, feel free to make better)
        It returns the following information (JSON-formatted) for the sample:
        + verdict
        + confidence
        + summary (attempt of writing a coherent and concise description for the user)
        + details (capturing more detailed information about how different categories of activity were determined)

        Note that as of right now, this content is formatted using Slack's version of markdown.
    """
    logger.info("message=Entering get_sample_summary() call")
    evidence = evidence_collector.EvidenceCollector(sample_id)
    evidence = evidence.collect_evidence(incoming_evidence
                                         , apikey
                                         , via_slack
                                         )
    if evidence is None:
        logger.info("sampleId=" + str(sample_id) + " message=Error collecting evidence. Got None.")
        return None
    verdict_info = get_sample_verdict(evidence)
    sample_summary = verdict_info
    sample_summary["summary"] = ""
    sample_summary["details"] = ""

    logger.info(" message=Getting modular items --")

    impacts = analysis.get_by_category("Impact", evidence)
    logger.info(" message=got impacts -> " + str(impacts))

    suspicious = analysis.get_by_category("Suspicious Activity", evidence)
    logger.info(" message=got suspicious -> " + str(suspicious))

    malicious = analysis.get_by_category("Malicious Activity", evidence)
    logger.info(" message=got malicious -> " + str(malicious))

    attack_vectors = analysis.get_by_category("Attack Vector", evidence)
    logger.info(" message=got attack_vectors -> " + str(attack_vectors))

    uninteresting_pageloads_section = prettyprint_uninteresting_pageloads(evidence)
    logger.info(" message=got uninteresting_pageloads_section -> " + str(uninteresting_pageloads_section))

    # common = analysis.get_by_category("Common Activity", evidence)
    sample_duration = analysis.get_sample_duration(evidence)
    logger.info(" message=got sample_duration -> " + str(sample_duration))

    bullet_text = ""
    summary_prefix = ("In this "
                      + str(int(sample_duration))
                      + " second sample, _NetworkSage_ has "
                      )
    details_prefix = "_NetworkSage_ has "
    details_general = (details_prefix
                       + "observed activity to:\n"
                       )
    bullet_text += prettyprint_bullets("Impact",
                                       impacts["known"],
                                       impacts["known_fqdns"],
                                       impacts["inferred"],
                                       impacts["inferred_fqdns"]
                                       )
    bullet_text += prettyprint_bullets("Malicious",
                                       malicious["known"],
                                       malicious["known_fqdns"],
                                       malicious["inferred"],
                                       malicious["inferred_fqdns"]
                                       )
    bullet_text += prettyprint_bullets("Suspicious",
                                       suspicious["known"],
                                       suspicious["known_fqdns"],
                                       suspicious["inferred"],
                                       suspicious["inferred_fqdns"]
                                       )
    bullet_text += prettyprint_bullets("Attack Vector",
                                       attack_vectors["known"],
                                       attack_vectors["known_fqdns"],
                                       attack_vectors["inferred"],
                                       attack_vectors["inferred_fqdns"]
                                       )
    if len(bullet_text) > 0:
        details_general += bullet_text

    details_activity = ""  # where to capture the Details text
    if verdict_info["verdict"] == "No Interesting Activity" or len(bullet_text) == 0:
        summary_general = (summary_prefix
                           + verdict_info["confidence"]
                           + " confidence that there is no activity to worry about. "
                           )
        sample_summary["summary"] += summary_general
        return sample_summary  # short-circuit here because there's absolutely nothing interesting
    elif verdict_info["verdict"] == "Attack Vector":
        summary_general = (summary_prefix
                           + "seen one or more Attack Vectors, but has not seen anything Suspicious, Malicious, or Impact-causing. Because of that, we don't think that there's anything to worry about. However, to be safe (especially because Malicious or Suspicious activity could have happened either before or after the bounds of this sample), we will include the aforementioned information in the details. "
                           )
    else:
        if len(suspicious["inferred"]) == 0 and len(malicious["inferred"]) == 0 and len(malicious["known"]) == 0:
            if (len(impacts["inferred"]) > 0 or len(impacts["known"]) > 0) and "phishing_detected" in evidence.sample_metadata:
                # handles scenarios where we think the phishing site is also the C2 site
                narrative = tell_sample_story(evidence, attack_vectors, suspicious, malicious, impacts)
                summary_general = summary_prefix + narrative
            else:
                summary_general = (summary_prefix
                                   + "seen some activity that looks like an Attack Vector and/or an Impact, we didn't see any activity that was Suspicious or Malicious. Because of that, we don't think that there's anything to worry about. However, to be safe (especially because Malicious or Suspicious activity could have happened either before or after the bounds of this sample), we will include the aforementioned information in the details. "
                                   )
        else:
            narrative = tell_sample_story(evidence, attack_vectors, suspicious, malicious, impacts)
            summary_general = summary_prefix + narrative
    details_general += "\nDetails about each are as follows:\n\n"
    # now go through things from Attack Vector to Mal to Sus to Impact
    details_activity += capture_details_by_category("Attack Vector"
                                                    , attack_vectors
                                                    , evidence.destination_data
                                                    )
    details_activity += capture_details_by_category("Malicious Activity"
                                                    , malicious
                                                    , evidence.destination_data
                                                    )
    details_activity += capture_details_by_category("Suspicious Activity"
                                                    , suspicious
                                                    , evidence.destination_data
                                                    )
    details_activity += capture_details_by_category("Impact"
                                                    , impacts
                                                    , evidence.destination_data
                                                    )
    sample_summary["summary"] += summary_general
    sample_summary["details"] = details_general + details_activity + uninteresting_pageloads_section
    # we save in sample_summary call so that any nearby categorization calls don't need to redo work

    logger.info(" message=sample summary -> " + str(sample_summary["summary"]))

    evidence.save_results_to_cache()
    return sample_summary


def tell_sample_story(evidence, attack_vectors, suspicious, malicious, impacts):
    """We want the information we share with users to be exceptionally clear and easy to understand. This function
        attempts to build out a compelling narrative about only the most critical information a user needs.
     run through what we've found and look for a story that we can share with the user that brings the elements
     together. If -- while looking for that story --This functionality is predominantly focused on samples that have
     clusters of data, because clusters allow us to find interesting stories.
    """
    all_avs = set()
    all_sus = set()
    all_mal = set()
    all_imp = set()
    all_avs.update(attack_vectors["known"])
    all_avs.update(attack_vectors["inferred"])
    all_sus.update(suspicious["inferred"])
    all_mal.update(malicious["known"])
    all_mal.update(malicious["inferred"])
    all_imp.update(impacts["known"])
    all_imp.update(impacts["inferred"])
    story = ""
    attack_vector_info = []
    phishing_info = []
    impact_info = []
    topic_info = []

    if "suspected_topic" in evidence.sample_metadata.keys():
        topic_info = [evidence.sample_metadata["suspected_topic"]]
    if "attack_vector_detected" in evidence.sample_metadata.keys():  # TODO: Make much better.
        attack_vector_info = [(evidence.sample_metadata["suspected_attack_vector"], "")]
    if "phishing_detected" in evidence.sample_metadata.keys():
        for dest in evidence.destination_data.keys():
            try:
                # print("Phishing detected, and we have full dest of", dest )
                for dest_and_port_record in evidence.destination_data[dest]["full_destinations"]:
                    inference_object = dest_and_port_record["inferences"]
                    if "is_phishing" in inference_object.associated_inferences.keys():
                        title = ""
                        try:
                            for g in dest_and_port_record["activity_groups"]:
                                if g.has_known_metadata:
                                    metadata = activity_grouping.get_highest_metadata_for_group(g)
                                    title = metadata["title"]
                                    break  # only need one of them
                        except:
                            title = ""
                        phishing_info += [(dest, title)]
                        break
                    else:
                        continue
            except:
                continue
    if "impact_detected" in evidence.sample_metadata.keys():
        for dest in evidence.destination_data.keys():
            try:
                for dest_and_port_record in evidence.destination_data[dest]["full_destinations"]:
                    inference_object = dest_and_port_record["inferences"]
                    if "information_collection" in inference_object.associated_inferences.keys():
                        title = ""
                        try:
                            for g in dest_and_port_record["activity_groups"]:
                                if g.has_known_metadata:
                                    metadata = activity_grouping.get_highest_metadata_for_group(g)
                                    title = metadata["title"]
                                    break  # only need one of them
                        except:
                            title = ""
                        impact_info += [(dest, title)]
                        break
            except:
                continue
    if len(attack_vector_info) > 0 and len(phishing_info) > 0:
        story += "evidence to suggest that a user clicked on "
        if attack_vector_info[0][1] != "":
            story += attack_vector_info[0][1]
        else:
            safe_link = attack_vector_info[0][0].replace(".", "[.]")
            story += ("a link hosted on "
                      + safe_link
                      + " "
                      )
    elif len(attack_vector_info) > 0 and len(phishing_info) == 0:
        story += "evidence to suggest that there is a user actively browsing the Internet"
    if len(phishing_info) > 0:
        safe_link = phishing_info[0][0].replace(".", "[.]")
        if len(attack_vector_info) == 0:
            story += ("evidence to suggest that somehow a user visited the *phishing* site "
                      + safe_link
                      )
        else:
            story += ("which led to the *phishing* site "
                      + safe_link
                      )
        if phishing_info[0][1] != "":
            story += (" (which is known as `"
                      + phishing_info[0][1]
                      + "`)"
                      )
        if len(topic_info) > 0:
            story += " targeting "
            if topic_info[0][0] == "generic":
                safe_link = topic_info[0][1].replace(".", "[.]")
                story += ("a popular brand or service either associated with or with assets hosted on "
                          + safe_link
                          )
            elif topic_info[0][0] == "brand" and topic_info[0][1] is not None:
                story += topic_info[0][1]
        story += "."
    if len(impact_info) > 0:
        safe_link = impact_info[0][0].replace(".", "[.]")
        story += (" We also believe that the user *entered information* (such as credentials) into "
                  + safe_link
                  )
        if impact_info[0][1] != "":
            story += (" (which is known as `"
                      + impact_info[0][1]
                      + "`)"
                      )
        story += ". This means that there's very likely *something to respond to* in this sample!"
    else:
        if attack_vector_info == [] and impact_info == [] and phishing_info == []:
            prefix = "some evidence to suggest that there is something of concern, but we're not certain. While there may be sites that seem "
            suffix = " in the underlying details, we can't confirm that those sites did anything that is actually noteworthy. A scenario where this may be true is when a malicious site has already been neutralized before the user visited it. It is highly recommended to analyze the underlying activity categorizations for more details."
            worst_category = "Malicious"
            if len(all_mal) == 0:
                worst_category = "Suspicious"
            story += prefix + worst_category + suffix
        elif len(attack_vector_info) > 0 and phishing_info == []:  # right now we can't have impact without phishing
            worst_category = "Suspicious"
            suffix = ""
            if len(all_mal) == 0:
                prefix = ", but no highly-concerning activity is visible."
                if len(all_sus) > 0:
                    suffix = " There are, however sites that have been identified as " + worst_category + " that may be worth analyzing more closely."
            else:
                worst_category = "Malicious"
                prefix = "."
            story += prefix + suffix
        else:
            story += (
                " We haven't observed any clear impact in this sample that (for example) would indicate that a user entered their credentials. To confirm, please review the sample details for activity after the phishing site."
            )
    story += " For additional details about the destinations mentioned above as well as any other possible destinations of concern, please review the `Details` section below.\n"
    return story


def get_sample_verdict(evidence):
    """This call takes in all collected evidence and returns the following information for the sample:
        + verdict
        + confidence
        We look first at Impact because Impact would be the worst-case (i.e. someone had credential stolen, a browser
        extension was installed). Second would be Malicious Activity (there's activity to a known-malicious site, but
        we weren't able to definitely identify Impact). Third would be Suspicious Activity (it's not definitely good,
        but it's also not clearly bad). Fourth would be Attack Vector (which means that something might be acting like
        a vector for an attack, but we didn't find anything suspicious or otherwise worrying). Finally, if there's only
        Common Activity, we label as No Interesting Activity.
    """
    verdict = ""
    confidence = ""

    impacts = analysis.get_by_category("Impact", evidence)
    suspicious = analysis.get_by_category("Suspicious Activity", evidence)

    if len(impacts["known"]) > 0:
        verdict = "Impact"
        confidence = "High"
    elif len(impacts["inferred"]) > 0:
        verdict = "Impact"
        if len(suspicious["inferred"]) > 0:
            confidence = "Medium-High"
        else:
            confidence = "Medium"
    # TODO: need to distinguish if impact is CONNECTED TO Sus site (via Inferences) to determine if it is Medium or Medium-High
    if confidence != "":
        answer = {"verdict": verdict
            , "confidence": confidence
                  }
        return answer

    malicious = analysis.get_by_category("Malicious Activity", evidence)
    if len(malicious["known"]) > 0:
        verdict = "Malicious Activity"
        confidence = "High"
    elif len(malicious["inferred"]) > 0:
        verdict = "Malicious Activity"
        confidence = get_highest_confidence(malicious["inferred"])

    if confidence != "":
        answer = {"verdict": verdict
            , "confidence": confidence
                  }
        return answer
    if len(suspicious["inferred"]) > 0:  # not possible to have known sus today
        verdict = "Suspicious Activity"
        confidence = get_highest_confidence(suspicious["inferred"])

        if confidence != "":
            answer = {"verdict": verdict
                , "confidence": confidence
                      }
            return answer

    attack_vectors = analysis.get_by_category("Attack Vector", evidence)
    if len(attack_vectors["known"]) > 0:
        verdict = "Attack Vector"
        confidence = "High"
    elif len(attack_vectors["inferred"]) > 0:
        verdict = "Attack Vector"
        confidence = get_highest_confidence(attack_vectors["inferred"])

    if confidence != "":
        answer = {"verdict": verdict
            , "confidence": confidence
                  }
        return answer
    common = analysis.get_by_category("Common Activity", evidence)
    if len(common["inferred"]) > 0:
        verdict = "No Interesting Activity"
        confidence = get_lowest_confidence(common["inferred"])

    if confidence == "":
        confidence = "Low"
    answer = {"verdict": verdict
        , "confidence": confidence
              }
    return answer


def get_categorized_activity_groups(sample_id=None, incoming_evidence=None, apikey=None, via_slack=False):
    """This call is meant to be an API endpoint exposed to the user as follows:
        https://api.seclarity.io/sec/v1.0/samples/"+uuid+"/activity/categorized (proposed, feel free to make better)
        takes in all collected evidence and returns the following information (JSON-formatted) for the sample:
        + Category Name (which category we're currently capturing)
            + Destination Name
                + Destination Groups
                    + Group Metadata

        Note that as of right now, the description for each destination is formatted using Slack's version of markdown.
    """
    logger.info("sampleId=" + str(sample_id) + " message=Entering get_categorized_activity_groups() call")
    evidence = evidence_collector.EvidenceCollector(sample_id)
    evidence = evidence.collect_evidence(incoming_evidence,
                                         apikey,
                                         via_slack=False
                                         )
    if evidence is None:
        logger.info("sampleId=" + str(sample_id) + " message=Error collecting evidence. Got None.")
        return None
    impacts = analysis.get_all_groups_by_category("Impact", evidence)
    suspicious = analysis.get_all_groups_by_category("Suspicious Activity", evidence)
    malicious = analysis.get_all_groups_by_category("Malicious Activity", evidence)
    attack_vectors = analysis.get_all_groups_by_category("Attack Vector", evidence)
    common = analysis.get_all_groups_by_category("Common Activity", evidence)

    results = {
        "Attack Vector": [],
        "Malicious Activity": [],
        "Suspicious Activity": [],
        "Impact": [],
        "Common Activity": []
    }

    categories_data = [attack_vectors
        , malicious
        , suspicious
        , impacts
        , common
                       ]
    categories_names = ["Attack Vector"
        , "Malicious Activity"
        , "Suspicious Activity"
        , "Impact"
        , "Common Activity"
                        ]
    count = 0
    for cat in categories_data:
        # iterate through the list above to correctly get all of the information into our format.
        if not cat:
            results[categories_names[count]] = cat  # populates an empty list if nothing existed for that category
            count += 1
            continue
        for entry in cat:
            dest = entry[0]
            group_objects = entry[1]
            groups_as_dicts = []
            for group in group_objects:
                groups_as_dicts += [group.prep_group_output(skip=["category"])
                                    ]  # exclude any internal-only keys from the groups
            results[categories_names[count]] += [{"destination": dest
                                                     , "activity_groups": groups_as_dicts
                                                  }]
        count += 1
    evidence.delete_cached_results()  # only keep around for one run of the APIs to avoid redoing work
    return results


def capture_details_by_category(category, category_dict, evidence):
    """Prints the details information for the user
    """
    cat_details = ""
    if not category.endswith("y"):
        plural_cat = category + "s"
    else:
        plural_cat = category[:-1] + "ies"
    known_length = len(category_dict["known_fqdns"])
    inferred_length = len(category_dict["inferred_fqdns"])

    if category != "Suspicious Activity":
        if known_length == 0:
            cat_details += "There are no known "
            if inferred_length == 0:
                cat_details += ("or suspected "
                                + plural_cat
                                + " in this sample.\n")
                # TODO: Leverage verdict info to make better decisions on what to write here!
            else:
                cat_details += (plural_cat + " in this sample, but there ")
                if inferred_length > 1:
                    cat_details += ("are " + str(inferred_length) + " which we suspect could be " + plural_cat + ". ")
                else:
                    cat_details += ("is " + str(inferred_length) + " which we suspect could be ")
                    if category[0] in ["A", "E", "I", "O", "U"]:
                        cat_details += "an "
                    else:
                        cat_details += "a "
                    cat_details += (category
                                    + ": \n"
                                    )
                # TODO: Leverage verdict info to make better decisions on what to write here!
        else:
            cat_details += "We have observed " + str(known_length) + " "
            if known_length == 1:
                cat_details += category
            else:
                cat_details += plural_cat
            cat_details += " in this sample:\n"
            count = 1
            for item in category_dict["known_fqdns"]:
                dest = item[0].split(":")[0]
                confidence = item[1]
                fqdn_port_pair_count = 1
                for dest_and_port_record in evidence[dest]["full_destinations"]:
                    groups = dest_and_port_record["activity_groups"]
                    title = activity_grouping.get_title_for_activity_group(groups[0])
                    description = activity_grouping.get_description_for_activity_group(groups[0])
                    first_seen = groups[0].first_seen_in_this_group
                    name = groups[0].destination_and_port
                    if fqdn_port_pair_count > 1:
                        cat_details += ("\tFor this same destination, we've also seen activity to `"
                                        + title
                                        + "` (first seen here at "
                                        + str(first_seen)
                                        + "s.)\n\t*Destination Name:* "
                                        + name
                                        + "\n\t*Description:* ```"
                                        + description
                                        + "```\n"
                                        )
                    else:
                        cat_details += ("\t"
                                        + str(count)
                                        + ". `"
                                        + title
                                        + "` (first seen here at "
                                        + str(first_seen)
                                        + "s.)\n\t*Destination Name:* "
                                        + name
                                        + "\n\t*Confidence:* "
                                        + confidence
                                        + "\n\t*Description:* ```"
                                        + description
                                        + "```\n"
                                        )
                    fqdn_port_pair_count += 1
                count += 1
    if inferred_length > 0:
        if known_length > 1 or category == "Suspicious Activity":
            cat_details += "We have observed " + str(inferred_length) + " suspected "
            if inferred_length == 1:
                cat_details += category
            else:
                cat_details += plural_cat
            cat_details += " in this sample:\n"
        count = 1
        for item in category_dict["inferred_fqdns"]:
            dest = item[0].split(":")[0]
            # dest = item[0][:item[0].rfind(":")]
            confidence = item[1]
            fqdn_port_pair_count = 1
            for dest_and_port_record in evidence[dest]["full_destinations"]:
                groups = dest_and_port_record["activity_groups"]
                title = activity_grouping.get_title_for_activity_group(groups[0])
                description = activity_grouping.get_description_for_activity_group(groups[0])
                first_seen = groups[0].first_seen_in_this_group
                if fqdn_port_pair_count > 1:
                    cat_details += ("\tFor this same destination, we've also seen activity to "
                                    + title
                                    + "` (first seen here at "
                                    + str(first_seen)
                                    + "s.)\n\t*Description:* ```"
                                    + description
                                    + "```\n"
                                    )
                else:
                    cat_details += ("\t"
                                    + str(count)
                                    + ". `"
                                    + title
                                    + "` (first seen here at "
                                    + str(first_seen)
                                    + "s.)\n\t*Confidence:* "
                                    + confidence
                                    + "\n\t*Description:* ```"
                                    + description
                                    + "```\n"
                                    )
                fqdn_port_pair_count += 1
            count += 1
    return cat_details


def get_highest_confidence(input_tuples):
    """Since we can have multiple confidence levels for different destinations within a category, this helps us to
        identify the highest confidence level.
    """
    highest_confidence = ""
    for item in input_tuples:
        if item[1] == "High":
            highest_confidence = item[1]
            break  # only need one high
        if item[1] == "Medium-High":
            highest_confidence = item[1]
            continue
        if item[1] == "Medium":
            highest_confidence = item[1]
            continue
        if item[1] == "Low":
            highest_confidence = item[1]
            continue
        if highest_confidence == "":
            if item[1] == "Medium":
                highest_confidence = item[1]
                continue
    return highest_confidence


def get_lowest_confidence(input_tuples):
    """Since we can have multiple confidence levels for different destinations within a category, this helps us to
        identify the lowest confidence level.
    """
    lowest_confidence = ""
    for item in input_tuples:
        if item[1] == "":
            lowest_confidence = item[1]
            break  # only need one non-existent
        if item[1] == "Medium":
            lowest_confidence = item[1]
            continue
        if lowest_confidence == "Medium":
            if item[1] == "Medium-High":
                lowest_confidence = item[1]
                continue
    return lowest_confidence


def prettyprint_uninteresting_pageloads(evidence):
    """Checks to see if we have any pageload information that we've ultimately identified as uninteresting. If so,
        prepares that for printing by capturing (in order of first seen time, ascending) each of the pages loaded. Also
        captures a bit of details about this information.
    """
    uninteresting_pageloads_summary = ""
    content = ""
    if "uninteresting_pageloads" in evidence.sample_metadata:
        pageload_records = evidence.sample_metadata["uninteresting_pageloads"]
        # first, order them by start time ascending
        groups = []
        for record in pageload_records:
            try:
                groups += [pageload_records[record][0]]
            except:
                logger.warning("Couldn't find the right data for suspected uninteresting pageload.")
                continue
        pageload_groups = sorted(groups
                               , key=lambda g: g.first_seen_in_this_group
                               )
        count = 1
        for group in pageload_groups:
            content += (
                str(count)
                + ". `"
                + group.destination_and_port
                + "` (first seen at "
                + str(group.first_seen_in_this_group)
                + "s.)\n"
            )
            count += 1
        if len(content) > 0:
            count -= 1  # we over-count by one since we also start at 1 instead of 0
            summary_prefix = "There "
            plural = ""
            if count == 1:
                summary_prefix += "is "
            else:
                summary_prefix += "are "
                plural = "s"
            summary_prefix += (str(count)
                               + " page"
                               + plural
                               + " loading in this sample that we do not believe to be interesting from a security "
                               + "perspective:\n"
                               )
            summary_suffix = "To view everything we know about "
            if count == 1:
                summary_suffix += "this "
            else:
                summary_suffix += "these "
            summary_suffix += ("destination"
                               + plural
                               + ", please review the sample's categorization data."
                              )
            uninteresting_pageloads_summary = summary_prefix + content + summary_suffix
    return uninteresting_pageloads_summary


def prettyprint_bullets(category, known, known_fqdns, inferred, inferred_fqdns):
    """Takes incoming lists of known and inferred sites for a given category and properly pretty-prints them to have
        correct pluralization and count. These are high-level details about each category, and whether they were KNOWN
        to be in that category or were inferred (i.e. by us, through our analysis).
    """
    text = ""

    if len(known_fqdns) > 0:
        text += ("• "
                 + str(len(known_fqdns))
                 + " known "
                 )
        if len(inferred_fqdns) > 0:
            text += ("and "
                     + str(len(inferred_fqdns))
                     + " suspected "
                     )
    elif len(inferred_fqdns) > 0:
        text += ("• "
                 + str(len(inferred_fqdns))
                 + " "
                 )
        if category != "Suspicious":  # suspected Suspicious sounds weird because it's redundant
            text += "suspected "
    else:
        return text  # there's nothing to add here
    text += ("`"
             + category
             + "` "
             )
    if category == "Impact":
        text += "-causing "
    text += "site"
    if len(known_fqdns) + len(inferred_fqdns) > 1:  # pluralization
        text += "s"
    text += "\n"
    return text
