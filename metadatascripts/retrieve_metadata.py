"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import ast
import datetime
import json
import logging
import sys

import requests
import constants
import utilities
from activitygroup import activity_grouping
from analyzesearchresults import analyze_search
from destinationproperties import whois_analysis, mispwarninglist_analysis
from events import events
from inferences import inference_analysis

logger = logging.getLogger("RetrieveMetadata")

"""This module collects metadata from NetworkSage about all the kinds of activities in a given sample.
"""


def collect_sample_metadata(sample_uuid, user_apikey, is_public=False):
    """Collects sample metadata using our public published API wrappers.
    """
    metadata = None
    if not is_public:
        if user_apikey is not None:
            response = requests.get(constants.SAMPLES_API_ENDPOINT + sample_uuid,
                                    headers={
                                        "apikey": user_apikey
                                    }
                                    )
            if not utilities.had_error(response):
                try:
                    result_json = json.loads(response.text)
                    metadata = result_json["body"]
                    if len(metadata) == 0:  # not yet processed
                        metadata = None
                except:
                    pass
    return metadata


def get_destinations_without_metadata(all_activities):
    """Captures information about destinations that have no Destination or Behavior metadata.
    """
    unknowns = dict()

    for activity in all_activities:
        if activity["destination"] != {} or activity["behavior"] != {}:
            continue
        else:
            destination = activity["secflow"]["destinationData"]
            global_count = activity["flowIdCount"]
            flow_category = activity["secflow"]["flowCategory"]
            if destination in unknowns.keys():
                unknowns[destination] += [{"global_count": global_count, "flow_category": flow_category}]
            else:
                unknowns[destination] = [{"global_count": global_count, "flow_category": flow_category}]
    return unknowns


def get_destinations_with_metadata(all_activities):
    """Captures information about destinations that have Destination or Behavior metadata.
    """
    knowns = []
    for activity in all_activities:
        if activity["destination"] != {} or activity["behavior"] != {}:
            if "flowIdCount" not in activity.keys():
                logger.error("ERROR!!!! need to get back flowId count EVERY time")
                activity["flowIdCount"] = 1  # dummy value for now.
            knowns += [activity]
        else:
            continue
    return knowns


def collect_ordered_activities_by_sample(sample_uuid, user_apikey=None, is_public=False):
    """Collects all activities (ordered ascending by relativeStart) from the sample passed in. Leverages our public API
        wrappers.
    """
    aggregated_activities = None
    endpoint = ""
    if not is_public:
        endpoint = constants.SAMPLES_API_ENDPOINT + sample_uuid + constants.PRIVATE_SAMPLE_AGGREGATED_DATA_API
        if user_apikey is not None:
            response = requests.get(
                endpoint,
                headers={
                    "apikey": user_apikey
                }
            )
        else:
            logger.error("Expected an API key but got None.")
            return None
    else:
        endpoint = constants.SECFLOWS_API_ENDPOINT + sample_uuid + constants.PUBLIC_SAMPLE_AGGREGATED_DATA_API
        response = requests.get(
            endpoint
        )
    if not utilities.had_error(response):
        try:
            result_json = json.loads(response.text)
            aggregated_activities = result_json["body"]
            if len(aggregated_activities) == 0:
                aggregated_activities = None
        except:
            logger.warning("Failed to get activities from "
                           + endpoint
                           + " endpoint."
                           )
            pass
    return aggregated_activities


def get_metadata_for_item(item_type, item, user_apikey, session=None):
    """Collects metadata from NetworkSage about requested items. Currently only supports Destination.
    """
    if user_apikey is None:
        logging.error("Expected a valid API key here but received None.")
        return None
    if item_type == "destination":
        dest_and_port = item
        destination = None
        endpoint_url = constants.DESTINATION_API_ENDPOINT + dest_and_port
        request_headers = {"apikey": user_apikey}
        if ":" not in dest_and_port:
            logger.error("Error: Must include a port for destination.")
            return None
        #result = requests.get(endpoint_url, headers=request_headers)
        if session is None:
            result = requests.get(endpoint_url, headers=request_headers)
        else:
            result = session.get(endpoint_url, headers=request_headers)
        if utilities.had_error(result):
            return destination
        result_json = json.loads(result.text)
        destination = result_json["body"]
        return destination
    else:
        logger.info("Unsupported item type " + str(item_type) + ". Aborting.")
        return None


def get_most_severe_category(full_destinations):
    """Since we can have more than one FQDN:port mapping for any given FQDN in a sample, we need to find the "worst"
        possible category that the destination could have.
    """
    quantitative_categories = []
    for name_and_port_entry in full_destinations:
        inference_category = name_and_port_entry["inferences"].category
        if inference_category == "Impact":
            quantitative_categories.append(5)
            break
        elif inference_category == "Malicious Activity":
            quantitative_categories.append(4)
        elif inference_category == "Suspicious Activity":
            quantitative_categories.append(3)
        elif inference_category == "Attack Vector":
            quantitative_categories.append(2)
        elif inference_category == "Common Activity":
            quantitative_categories.append(1)
        else:
            quantitative_categories.append(0)
    initial_category = "Suspicious Activity"
    max_cat = max(quantitative_categories)
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
    else:
        most_severe_category = initial_category
    return most_severe_category


def discover_partially_known(unknowns, knowns, all_activities, apikey):
    """Takes a list of unknown destinations and attempts to discover (first through the known activities in this sample,
        then through the NetworkSage database) whether we know anything about the parent domains of any of the domains.
        If we do and we think it's something we can use, we update the unknown to a known. This seems to be unreliably
        returning right now, so not sure what's going on...but ultimately we should use this to suggest Destinations
        that should be populated into our database so that we can collect more data and avoid hitting the DB so much.
    """
    discovered = []
    candidates = dict()
    usable_tags = ["Tracking", "Analytics"]
    for destination in unknowns:
        if utilities.get_destination_type(destination.split(":")[0]) == "IP":
            continue
        if destination.count(".") < 2:  # we need to at least have a subdomain to a domain
            continue
        unknown_length_2 = ".".join(destination.split(".")[-2:])
        try:
            unknown_length_3 = ".".join(destination.split(".")[-3:])
        except:
            unknown_length_3 = ""
        # check the known list first
        parent = None
        for known_dest_details in knowns:
            known_dest = known_dest_details["secflow"]["destinationData"]
            if "destination" not in known_dest_details.keys() or "title" not in known_dest_details[
                "destination"].keys():
                continue
            if unknown_length_3 == known_dest:  # we'd like the highest metadata first
                parent = known_dest
                break
            elif unknown_length_2 == known_dest:
                parent = known_dest_details["destination"]
                break
        if parent is not None:
            logger.info("We know about "
                         + str(destination)
                         + " by way of "
                         + str(parent)
                         )
            candidates[destination] = parent
            continue
        db_results = utilities.get_subdomain_details_by_name(destination, apikey)
        if db_results is None:
            logger.info("Got None from NetworkSage database call.")
            continue
        for result in (db_results[1:]):  # ignore most specific, because it's our exact match
            if "title" in result.keys():
                parent = result
                break
        if parent is not None:
            candidates[destination] = parent
            continue
    if len(candidates) > 0:
        for destination in candidates.keys():
            usable = False
            found_dest_tags = []
            found_actpurpose_tags = []
            if "activityPurposeTags" in candidates[destination].keys() and len(
                    candidates[destination]["activityPurposeTags"]) > 0:
                try:
                    activitypurpose_tags = ast.literal_eval(candidates[destination]["activityPurposeTags"])
                except:
                    activitypurpose_tags = candidates[destination]["activityPurposeTags"]
                for tag in usable_tags:
                    if tag in activitypurpose_tags:
                        found_actpurpose_tags += [tag]
                        usable = True
            if "destinationTags" in candidates[destination].keys() and len(
                    candidates[destination]["destinationTags"]) > 0:
                try:
                    destination_tags = ast.literal_eval(candidates[destination]["destinationTags"])
                except:
                    destination_tags = candidates[destination]["destinationTags"]
                for tag in usable_tags:
                    if tag in destination_tags:
                        found_dest_tags += [tag]
                        usable = True
            if usable:
                derived_title = ""
                derived_description = ""
                if len(found_dest_tags + found_actpurpose_tags) > 0:
                    title_tag = ""
                    if len(found_actpurpose_tags) > 0:
                        title_tag = found_actpurpose_tags[0]
                    elif len(found_dest_tags) > 0:
                        title_tag = found_dest_tags[0]
                    derived_title = (title_tag + " via " + candidates[destination]["title"])
                    derived_description = (
                            "This activity was automatically populated because we knew about its parent domain. Details for the parent: "
                            + candidates[destination]["description"]
                    )
                    logger.info("In discover_partially_known() call for destination " + destination)
                    logger.info("\tNew title: "
                                 + derived_title
                                 )
                    logger.info("\tNew description: "
                                 + str(derived_description)
                                 )
                for activity in all_activities:
                    if activity["secflow"]["destinationData"] == destination:
                        try:
                            activity["destination"] = {"platformHintTags": ""
                                , "associatedAppOrServiceTags": ""
                                , "description": derived_description
                                , "impactsTags": ""
                                , "activityPurposeTags": json.dumps(found_actpurpose_tags)
                                , "title": derived_title
                                , "attackVectorTags": ""
                                , "relevance": ""
                                , "threatTags": ""
                                , "securityTags": ""
                                , "destinationTags": json.dumps(found_dest_tags)
                                                       }
                            try:
                                del unknowns[destination]
                                logger.info("Successfully removed "
                                             + destination
                                             + " from Unknowns"
                                             )
                            except:
                                continue  # only works the first time
                        except:
                            logger.info("Failed to update activity for " + destination)
                            continue
                        discovered += [activity]
    return ((knowns + discovered), unknowns)


def collect_activity_info_about_destinations(evidence, destination_list, activity_dict, is_known,
                                             analyzed_manual_sandbox_results=None, path_to_sandbox_data=None):
    """For both known and unknown destinations, collects information about them based on the way each is acting in the
        sample. For those that are unknown (i.e. no metadata in NetworkSage), also collect information from the Internet
        search results and WHOIS information to complete our OSINT knowledge.
    """

    if not is_known:
        # For the unknowns, collect what we know about them from Internet search results and other active, time-related stuff.
        # analyzed_search_results = analyze_search.collect_destination_verdicts(destination_list)
        whois_results = whois_analysis.collect_whois(destination_list)
        all_root_domains_by_whois = whois_analysis.get_root_domains(whois_results)
        mispwarninglist_results = mispwarninglist_analysis.collect_matches(destination_list + all_root_domains_by_whois)
        evidence.sample_metadata["unknown_in_sample"] = destination_list
    else:
        evidence.sample_metadata["known_in_sample"] = activity_dict

    for destination in destination_list:
        destination_without_port = destination[:destination.rfind(":")]
        if destination_without_port not in evidence.destination_data.keys():
            evidence.destination_data[destination_without_port] = dict()
        evidence.destination_data[destination_without_port][
            "initial_osint_knowledge"] = None  # we don't have initial OSINT here.
        if "inferences" in evidence.sample_metadata.keys():
            inference_object = inference_analysis.get_object(
                destination
                , evidence.sample_metadata["inferences"]
            )
        else:
            inference_object = None
        if "activity_groups" in evidence.sample_metadata.keys():
            activity_groups = activity_grouping.get_activity_groups_for_destination(
                destination
                , evidence.sample_metadata["activity_groups"]
            )
        else:
            activity_groups = None
        if "full_destinations" not in evidence.destination_data[destination_without_port].keys():
            evidence.destination_data[destination_without_port]["full_destinations"] = []
        if evidence.destination_data[destination_without_port]["full_destinations"] == []:
            evidence.destination_data[destination_without_port]["full_destinations"].append(
                {"name_and_port": destination,
                 "inferences": inference_object,
                 "activity_groups": activity_groups
                 }
            )
        else:
            captured = False
            for dest_and_port_record in evidence.destination_data[destination_without_port]["full_destinations"]:
                if destination == dest_and_port_record["name_and_port"]:
                    captured = True
                    break
            if not captured:
                evidence.destination_data[destination_without_port]["full_destinations"].append(
                    {"name_and_port": destination,
                     "inferences": inference_object,
                     "activity_groups": activity_groups
                     }
                )
        if "inferences" in evidence.sample_metadata.keys():
            """ When we have inferences and we have WHOIS results for a given unknown (to NetworkSage) destination, try 
                to avoid hitting active search as much as possible. To do so, take the following steps:
                    1. See if the FQDN is in MISP's warning lists (which help us to avoid various common destinations) 
                        a. If it's not AND the FQDN is at least 3 "segments" long ("a.b.tld") AND it's not built on a
                            trusted CloudHostingPlatform, get the FQDN's "root domain" ("b.tld" in the above).
                        b. From the above, check the MISP warning lists again. If still not in there, look at search. 
                           This will allow us to first see if we have this "root domain" cached (which will allow us to
                           only hit search actively for things like "b.tld" instead of "x.y.z.b.tld", "z.b.tld", and so 
                           on [so at most we should have just one cached result for every site out there that ISN'T a 
                           built on trusted site and ISN'T in MISP's warning lists, which should cover a large number of
                           sites]).
                           HOWEVER, if we find that the site we've searched (cached or not) has a verdict that isn't 
                           Benign or Likely Benign AND ONE of the following, we'll hit search (cached if it exists, 
                           otherwise active) for this specific destination (because it probably makes sense to do so):
                                * There are search results for the parent
                                * The domain is at least 3 days old (from the time we actually captured the traffic)
                                * The domain is at least 3 days old (from the time we reviewed the traffic [in cases 
                                    where we don't get the actually correct capture time])
                                ^ The above stuff is brand new and not tested, so we should make sure it makes sense.
                    2. If whatever domain (parent or FQDN) is in MISP's warning lists, we'll store that information and
                        forego search. 
                search results (ideally, from cache). When we have nothing useful there, then we can go ahead and hit
                search results for this destination. Note that this logic is done at the destination (without port) 
                level, since results for specifically this destination on this port are extremely unlikely.
            """
            if not is_known:
                if "traffic_date" in evidence.sample_metadata.keys():
                    captured = datetime.datetime.fromtimestamp(float(evidence.sample_metadata["traffic_date"]))
                    whois_age = whois_analysis.get_domain_age_by_whois(whois_results[destination_without_port],
                                                                       to_captured=True,
                                                                       captured_datetime=captured
                                                                       )
                else:
                    whois_age = whois_analysis.get_domain_age_by_whois(whois_results[destination_without_port])
                if utilities.get_destination_type(destination_without_port) == "domain":
                    search_domain = destination_without_port
                else:
                    search_domain = None
                try:
                    if (
                            (search_domain not in mispwarninglist_results
                             or mispwarninglist_results[search_domain] == None
                            )
                            and search_domain.count(".") >= 2
                            and "built_on_trusted" not in evidence.destination_data[search_domain][
                        "full_destinations"][-1]["inferences"].associated_inferences.keys()
                    ):
                        logger.info(search_domain
                                    + " has no MISP WL results, is 3+ levels deep, and doesn't have"
                                    + " built on trusted in its inferences.")
                        root_domain = whois_analysis.get_root_domain_by_whois(whois_results[search_domain])
                        if root_domain is not None:
                            evidence.destination_data[destination_without_port]["root_domain_by_whois"] = root_domain
                        search_domain = evidence.destination_data[destination_without_port]["root_domain_by_whois"]
                        # print("Instead of hitting search for", destination_without_port, "we are using its root domain from whois:", search_domain)
                except:
                    # print("Something went wrong while trying to get RDBW for", destination_without_port, "so we're searching the Internet for it directly.")
                    search_domain = destination_without_port  # IP addresses will be reassigned to search_domain here
                if search_domain not in mispwarninglist_results or mispwarninglist_results[search_domain] == None:
                    if (whois_age is None or (whois_age is not None and whois_age.days >= 7)):
                        logger.info("Performing search for " + str(search_domain))
                        analyzed_search_results = analyze_search.collect_destination_verdicts([search_domain])
                        search_data = analyzed_search_results[search_domain]
                        analyzed_search_results[
                            destination_without_port] = search_data  # assign parent's search results to child
                        evidence.destination_data[destination_without_port]["parent_search_results"] = True
                        # print("Search data for", search_domain, "is:", search_data.risk, search_data.category, search_data.evidence)
                    else:
                        logger.info("Skipping search because site was less than 1 week old.")
                    try:
                        if (search_domain != destination_without_port
                                and search_data.risk not in ["Benign", "Likely Benign"]
                                and (search_data.total_results > 0
                                     or (whois_age is not None and whois_age.days > 2)
                                )
                        ):
                            logger.info("Decided to do an actual search for potentially interesting domain"
                                         + str(destination_without_port)
                                         )
                            # overwrite our parent's search result because it seems like things could be interesting...
                            analyzed_search_results = analyze_search.collect_destination_verdicts(
                                [destination_without_port])
                    except:
                        logger.info(
                            "Something errored out while trying to understand root domain's trustworthiness. Defaulting to its search results.")
                else:
                    # print("We found", search_domain, "in", len(mispwarninglist_results[search_domain]), "MISP warning lists:")
                    # print(mispwarninglist_results[search_domain])
                    # print("...So we're NOT going to do a search!")
                    if search_domain != destination_without_port:
                        evidence.destination_data[destination_without_port]["misp_warning_lists"] = \
                        mispwarninglist_results[search_domain]
                    else:
                        evidence.destination_data[search_domain]["misp_warning_lists"] = mispwarninglist_results[
                            search_domain]
            evidence.destination_data[destination_without_port]["initial_category"] = \
                get_most_severe_category(evidence.destination_data[destination_without_port]["full_destinations"])
        else:
            if not is_known:
                evidence.destination_data[destination_without_port]["initial_category"] = "Suspicious Activity"
        if "activity_groups" in evidence.sample_metadata.keys():
            if is_known:
                activity_grouping.update_confidence_for_destination(evidence.sample_metadata["activity_groups"]
                                                                    , "High"
                                                                    )  # set up confidence here for known activity
        else:
            evidence.destination_data[destination_without_port]["full_destinations"][-1][
                "activity_groups"] = []  # this handles cases where we're doing destination analysis
        if not is_known:
            evidence.destination_data[destination_without_port][
                "manual_sandbox_interesting_data"] = None  # we don't have manual sandbox data here.
            if activity_dict is not None and destination in activity_dict.keys():
                evidence.destination_data[destination_without_port]["unknown_destination_data"] = activity_dict[
                    destination]
            try:
                evidence.destination_data[destination_without_port]["search_result_analysis"] = analyzed_search_results[
                    destination_without_port]
            except:
                evidence.destination_data[destination_without_port]["search_result_analysis"] = None
            evidence.destination_data[destination_without_port]["whois_data"] = whois_results[destination_without_port]
            # only do these additional things if we have sandbox data.
            if analyzed_manual_sandbox_results is not None:
                for dest in analyzed_manual_sandbox_results.keys():
                    for dict_item in analyzed_manual_sandbox_results[dest]:
                        if "destination_resolved" in dict_item.keys() and dict_item["destination_resolved"] is not None:
                            if destination_without_port in dict_item["destination_resolved"]:
                                evidence.destination_data[destination_without_port]["manual_sandbox_interesting_data"] = \
                                    analyzed_manual_sandbox_results[dest]
                        else:
                            continue


def gather_sample_metadata(evidence, user_apikey=None, analyzed_manual_sandbox_results=None, path_to_sandbox_data=None):
    """Takes a NetworkSage sample as input and collects everything we need to perform analysis. Stores that information
        in the evidence object we also pass in.
    """
    is_public = True if "is_public" in evidence.sample_metadata.keys() and evidence.sample_metadata[
        "is_public"] else False
    if is_public and user_apikey is not None:
        logger.info("Provided an API key but still gathering metadata from a public sample...weird.")
    all_activities = collect_ordered_activities_by_sample(evidence.sample_metadata["uuid"], user_apikey, is_public)
    if all_activities is None:
        logger.info("Got no activities. Either we're not the sample owner or the sample had no activity!")
        return False
    else:
        logger.info("Got " + str(len(all_activities)) + " activities for this sample.")
    # create events metadata in code -- NOT implemented
    all_activities = events.identify_events(all_activities)
    logger.info("About to call get_destinations_with_metadata")
    knowns = get_destinations_with_metadata(all_activities)
    logger.info("About to call get_destinations_without_metadata")
    unknowns = get_destinations_without_metadata(all_activities)
    logger.info(
        "Trying to get information about the unknowns either from our knowns in this sample or from the database")
    (knowns, unknowns) = discover_partially_known(unknowns, knowns, all_activities, user_apikey)  # update list of knowns here
    # begin to collect inference information for each destination
    labeled_activities = inference_analysis.label_initially_interesting(all_activities)
    activity_groups = activity_grouping.create_activity_groups(labeled_activities)
    buckets = inference_analysis.perform_initial_bucketing(labeled_activities, activity_groups)
    known_names = set()
    for act in knowns:
        known_names.add(act["secflow"]["destinationData"])
    all_inference_objects = inference_analysis.collect_inferences(labeled_activities
                                                                  , buckets
                                                                  , activity_groups
                                                                  , knowns
                                                                  , user_apikey
                                                                  )
    evidence.sample_metadata["activity_groups"] = activity_groups
    evidence.sample_metadata["inferences"] = all_inference_objects
    logger.info("Calling collect_activity_info_about_destinations()")
    collect_activity_info_about_destinations(evidence
                                             , list(unknowns.keys())
                                             , unknowns
                                             , is_known=False
                                             )
    collect_activity_info_about_destinations(evidence
                                             , known_names
                                             , knowns
                                             , is_known=True
                                             )
    sample_details = collect_sample_metadata(evidence.sample_metadata["uuid"], user_apikey, is_public)
    if sample_details is not None:
        # collect the datetime that the sample was created so that we can compare that to any WHOIS data we collect
        evidence.sample_metadata["traffic_date"] = sample_details["trafficDate"]
        evidence.sample_metadata["uuid"] = sample_details["hash"]
        logger.info("Collected traffic date and UUID for private sample.")
    else:
        if is_public:
            logger.info("Received a public sample `"
                         + evidence.sample_metadata["uuid"]
                         + "` that causes us to miss our traffic date information!"
                         )
    return True
