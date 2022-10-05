"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import ast
import ipaddress
import json
import logging
import re
from itertools import groupby, count

import utilities
from activitygroup import activity_grouping
from destinationproperties import whois_analysis
from inferences import inference_collector
from metadatascripts import retrieve_metadata

logger = logging.getLogger("InferenceAnalysis")

"""This module contains all of our Inference analysis. Inferences are information that we can infer about some activity
    or group of activity based on how it's acting or interacting with other activities in a sample.
"""

interval_duration = 5  # global variable to identify what interval duration should be used in this sample
interesting_flow_categories = ["largeUpload"
    , "smallUpload"
    , "asNeededChannel"
    , "unclassified"
    , "continuousClientChannel"
    , "continuousServerChannel"
    , "unidirectional"
    , "minorContentDownloadedQuickly"
    , "someContentDownloadedQuickly"
    , "majorContentDownloadedQuickly"
    , "minorResourcesDownloadedQuickly"
    , "someResourcesDownloadedQuickly"
    , "majorResourcesDownloadedQuickly"
    , "minorContentDownloaded"
    , "someContentDownloaded"
    , "majorContentDownloaded"
    , "minorResourcesDownloaded"
    , "someResourcesDownloaded"
    , "majorResourcesDownloaded"
    , "minorDataDownloadedViaLongSession"
    , "someDataDownloadedViaLongSession"
    , "majorDataDownloadedViaLongSession"
    , "singleResourceLoaded"]
org_hiding_registrars = ["DATA REDACTED"
    , "Whois Privacy Service"
    , "Domains By Proxy, LLC"
    , "Privacy service provided by Withheld for Privacy ehf"
    , "Whois Privacy Protection Service, Inc."
    , "REDACTED FOR PRIVACY"
    , "WhoisSecure"
    , "Whoisprotection.cc"
    , "See PrivacyGuardian.org"
    , "GDPR Masked"
    , "Whois Privacy Protection Service by MuuMuuDomain"
    , "Private Person"
    , "Statutory Masking Enabled"
                         ]  # these provide meaningless information for identifying a true organization
org_hiding_registrars_regex = r'^(Contact Privacy Inc.)'  # same as above, but these have additional metadata
common_ports = ["443", "53", "80", "22", "3389"]


def get_merged_cluster_intervals(ordered_cluster_intervals_dict, step_interval):
    """In order to do the best bucketing and identification of activity possible in each sample, we want to be able to
        understand when our default interval_duration buckets aren't ideal. This function allows us to take all of the
        knowledge we learned from clusters and distill it down into the set of buckets that should actually be used for
        the sample. We return a list of lists, where each internal list captures the interval start times that should be
        merged together.
    """
    merged_intervals = []
    merged_clusters_dict = dict()
    for cluster in ordered_cluster_intervals_dict.keys():
        groups = groupby(ordered_cluster_intervals_dict[cluster]
                         , key=lambda item
                                      , c=count(step=step_interval): item - next(c)
                         )
        merged_clusters_dict[cluster] = groups
        tmp = [list(g) for k, g in groups]
        merged_clusters_dict[cluster] = tmp
    # print("Merged Clusters:", merged_clusters_dict)
    allgroups = list(merged_clusters_dict.values())
    sgroups = sorted(allgroups)
    fingroups = []
    for g in sgroups:
        fingroups += g
    # sort them so that we have things with consecutive intervals next to each other
    fingroups = sorted(fingroups)
    # print("sorted groups:", fingroups)
    position = 0
    for g in fingroups:
        if merged_intervals == []:
            merged_intervals += [g]  # grab the first group regardless
            position += 1
            continue
        else:
            captured_dict = {"captured": []
                , "to_capture": []
                             }
            for val in g:
                if val in merged_intervals[-1]:
                    captured_dict["captured"] += [val]
                else:
                    captured_dict["to_capture"] += [val]
            if len(captured_dict["captured"]) > 0:
                merged_intervals[-1] = sorted(
                    list(set(merged_intervals[-1] + captured_dict["to_capture"])))  # add new adjacent members to group
            else:
                merged_intervals += [captured_dict["to_capture"]]
    # print("Final values:", merged_intervals)
    return merged_intervals


def get_merged_interval_duration(merged_intervals, current_interval_start):
    duration = interval_duration  # default interval duration (Global)
    for interval in merged_intervals:
        if current_interval_start in interval:
            duration = interval[-1] - interval[
                0] + interval_duration  # adding duration allows us to correctly get end time
            break
    return duration


def perform_initial_bucketing(labeled_activities, activity_groups):
    """This step happens BEFORE Inferences can be computed. In here, we must collect (from ALL activities in the sample)
        interval_duration second buckets (by relative start time) of activity to the same destination with the same flow
        category. Whenever we know that a bucket is adjacent to another related bucket (which comes from knowing about
        associated clusters from our activity groups), we merge buckets into larger intervals. This helps with later
        needs for more advanced processing. Each bucket in the list should contain a dictionary that contains min
        relative start of the group, the flow category, and the destination name. Additionally, the actual activities
        collected in that bucket should be captured.
    """
    buckets = []
    bucket_items = dict()

    # prep some related topics
    cluster_activity(activity_groups)
    ordered_clusters = get_clusters_by_start_time(activity_groups)
    ordered_cluster_intervals_dict = get_cluster_intervals(ordered_clusters, step_interval=interval_duration)
    # print("Ordered clusters:", ordered_cluster_intervals_dict)
    interval_start = 0
    merged_intervals = get_merged_cluster_intervals(ordered_cluster_intervals_dict, step_interval=interval_duration)
    # now, instead of bucketing by a fixed interval duration, we'll use any merged interval periods.

    current_interval_start = 0  # always start at the beginning of the file.
    for activity in labeled_activities:
        bucket_interval = get_merged_interval_duration(merged_intervals,
                                                       current_interval_start)  # returns default interval if none found
        secflow_data = activity["secflow"]
        if current_interval_start <= float(secflow_data["relativeStart"]) < current_interval_start + bucket_interval:
            # it is in this bucket range
            key = secflow_data["destinationData"] + secflow_data["flowCategory"]
            if key in bucket_items.keys():
                # it was already in bucket, so we're adding this activity to the list
                bucket_items[key]["activities"] += [activity]
            else:
                # was NOT already in bucket, so we're creating this entry now
                bucket_items[key] = {"minRelativeStart":
                                         secflow_data["relativeStart"]
                    , "destinationData":
                                         secflow_data["destinationData"]
                    , "flowCategory":
                                         secflow_data["flowCategory"]
                    , "activities": [activity]
                                     }
        if len(bucket_items) > 0:
            buckets += [bucket_items]  # store the ones we've already captured
        current_interval_start += bucket_interval  # move onto next interval
        bucket_items = dict()  # reset the dictionary
        # capture this activity in new bucket
        key = secflow_data["destinationData"] + secflow_data["flowCategory"]
        bucket_items[key] = {"minRelativeStart":
                                 secflow_data["relativeStart"]
            , "destinationData":
                                 secflow_data["destinationData"]
            , "flowCategory":
                                 secflow_data["flowCategory"]
            , "activities": [activity]
                             }
    return buckets


def get_object(dest, all_inference_objects):
    """ For a given destination, get back the inference object and its category as a tuple.
    """
    for category in all_inference_objects.keys():
        if dest in all_inference_objects[category].keys():
            return all_inference_objects[category][dest]
    return None


def get_inferences_from_verdicts(destination_and_port, verdicts):
    dest_sans_port = utilities.dest_without_port(destination_and_port)
    try:
        for d in verdicts["destinations"][dest_sans_port]["full_destinations"]:
            if d["name_and_port"] == destination_and_port:
                return d["inferences"].associated_inferences
    except:
        logger.warning("Failed to get inference object for destination.")
    return None


def get_subclusters(activity_groups, ordered_clusters=None):
    """This is a preparation step that takes all activity groups and for each associated cluster (or groups that are
        unclustered), organizes each of those groups into clusters by start time. Adjacent subclusters are merged. These
        subclusters are written to the Activity Group record, so nothing is passed back.
    """
    subcluster_tolerance = 2.0  # how far apart the start times of a group can be (in seconds)
    subcluster = []
    subclusters = []
    unclustered = []
    if ordered_clusters is None:
        ordered_clusters = get_clusters_by_start_time(activity_groups)
    for group in activity_groups:
        if group.associated_cluster == -1:
            unclustered += [group]
    for c in ordered_clusters:
        try:
            first = ordered_clusters[c][0].first_seen_in_this_group  # earliest time in that cluster
        except:
            first = 0.0
        # print("Cluster", c, "has the following data:")
        for group in ordered_clusters[c]:
            # print(group.destination_and_port, "first seen at", group.first_seen_in_this_group)
            if group.first_seen_in_this_group > first + subcluster_tolerance:
                # auto-merge adjacent intervals
                if group.first_seen_in_this_group <= (first + (subcluster_tolerance * 2)):
                    # print("This is an adjacent interval, so we'll auto-merge")
                    subcluster += [group]
                    continue  # we don't want to update our first time here, since this is part of an adjacent interval
                # save any existing subclusters
                if len(subcluster) > 0:
                    subclusters += [subcluster]
                    # print("Saving previous subcluster to subclusters")
                first = group.first_seen_in_this_group  # start of a new subcluster
                # print("New subcluster found at", first)
                subcluster = [group]
            else:
                subcluster += [group]  # just add to the existing subcluster
    subs_with_unclustered = []
    for unclustered_group in unclustered:  # add all the unclustered groups to the proper subclusters
        found = False
        for sub in subclusters:
            try:
                earliest = sub[0].first_seen_in_this_group
                latest = sub[-1].first_seen_in_this_group
            except:
                continue
            # print("CHECKING unclustered group for", unclustered_group.destination_and_port, "starting at", unclustered_group.first_seen_in_this_group, "against subcluster with earliest of", earliest, "and latest of", latest)
            if earliest <= unclustered_group.first_seen_in_this_group <= latest:
                sub += [unclustered_group]
                sub = sorted(sub
                             , key=lambda s: s.first_seen_in_this_group
                             )  # make sure we're still sorted ascending
                # print("Adding unclustered group for", unclustered_group.destination_and_port, "starting at", unclustered_group.first_seen_in_this_group, "to subcluster with earliest of", earliest, "and latest of", latest)
                found = True
                break
        # if not found:
        #    print("Unclustered group for", unclustered_group.destination_and_port, "starting at", unclustered_group.first_seen_in_this_group, "NOT added anywhere.")
    pos = 0
    for sub in subclusters:
        if len(sub) == 1:
            continue
        for g in sub:
            g.subcluster = pos
            # print(g.destination_and_port, "in CLUSTER", g.associated_cluster, "with first_seen_in_this_group of", g.first_seen_in_this_group, "assigned to subcluster", g.subcluster)
        pos += 1


def cluster_activity(activity_groups):
    """This is a preparation step only. When we see more than one destination ending within 0.5 seconds and it's NOT
        the end of the file, we'll say that they're clustered. Save in the activity group object.
    """
    # first, make sure we're in ascending last_seen_in_this_group order
    activity_groups = sorted(activity_groups
                             , key=lambda g: g.last_seen_in_this_group
                             )
    last = 0.0
    cluster_tolerance = 0.75  # 0.5 how far apart the ends of a group can be (in seconds)
    clustered_group = []
    clusters = []
    for group in activity_groups:
        if group.last_seen_in_this_group > cluster_tolerance + last:
            last = group.last_seen_in_this_group
            if len(clustered_group) == 0:
                clustered_group = [group]  # start w/ new group each time
                continue  # nothing interesting
            clusters += [clustered_group]
            clustered_group = [group]  # start w/ new group each time since we're no longer clustered
            continue
        clustered_group += [group]
        clusters += [
            clustered_group]  # maybe adds last cluster in sample? If things start getting wonky, remove this line
        # NOTE: this implicitly doesn't include the group that ends the sample, since we don't save the very last group we see when ordered by last_seen time
    pos = 0
    for c in clusters:
        if len(c) == 1:
            continue
        for g in c:
            g.associated_cluster = pos
        pos += 1


def get_clusters_by_start_time(activity_groups):
    """This is a preparation step only. Takes all activity groups and for those that are in a cluster, orders them by
        their first_seen_in_this_group time.
    """
    clusters = dict()

    for g in activity_groups:
        # if g.associated_cluster == -1:
        #    continue
        if g.associated_cluster in clusters.keys():
            clusters[g.associated_cluster] += [g]
        else:
            clusters[g.associated_cluster] = [g]
    for cluster in clusters.keys():
        clusters[cluster] = sorted(clusters[cluster]
                                   , key=lambda g: g.first_seen_in_this_group
                                   )
    return clusters


def get_cluster_intervals(ordered_clusters, step_interval=interval_duration):
    """This is a preparation step only. For each ordered cluster, finds the interval_duration second wide interval start
        times that it contains. Returns those in order (ascending).
    """
    cluster_dict = {}
    # print("Ordered clustes:", ordered_clusters)
    for c in ordered_clusters:
        if c == -1:
            continue
        cluster_dict[c] = set()
        for g in ordered_clusters[c]:
            cluster_dict[c].add(int(g.first_seen_in_this_group // step_interval) * step_interval)
        cluster_dict[c] = sorted(cluster_dict[c])  # make sure each cluster has its intervals sorted ascending
    return cluster_dict


def label_initially_interesting(incoming_activities):
    """This step happens before Inferences can be computed, and is equivalent in result to that of the old "What's
        Interesting -- First Pass" capability.
    """
    for activity in incoming_activities:
        # only consider those that don't have metadata
        if (activity["destination"] == {}
                and activity["behavior"] == {}
                and "event" in activity.keys()
                and (activity["event"] == {}
                     or activity["event"] == "null")
        ):
            if activity["secflow"]["flowCategory"] in interesting_flow_categories:
                activity["interesting"] = True
            else:
                activity["interesting"] = False
        else:
            activity["interesting"] = True
    return incoming_activities


def has_other_interesting(activity_groups, excluded_categories=[]):
    """This is used to identify if some destination has other activity that is interesting that excludes anything coming
        into this function as an excluded category.
    """
    remaining_interesting = [cat for cat in interesting_flow_categories if cat not in excluded_categories]
    for g in activity_groups:
        for activity in g.overlapping_activities:
            if activity["secflow"]["flowCategory"] in remaining_interesting:
                return True
    return False


def collect_meta_buckets(activity_groups):
    """Function that collects buckets of buckets for more advanced analysis. Steps:
    1. Group all activity from a sample into interval_duration second buckets (or into their merged bucket intervals) by
        their relative start times. Also count the number of total flows in the bucket.
    2. For each destination in a bucket, capture the COUNT of times we’ve seen it in that bucket (for example, if there
        are 5 singleResourceLoaded flows to destination x, the count is 5. If there are 2 singleResourceLoaded flows and
        3 majorContentDownloaded flows, the count is still 5).
    3. Sum the entire bucket’s destination bytes.
    4. If the bucket’s count isn’t at least 3 and the total destination bytes isn’t at least 200KB, throw it away.
    """
    interval_start_time = 0
    logger.info("Inside collect_meta_buckets() call")
    collection_dict = dict()
    subcluster_dict = dict()  # Activity Groups by subcluster ID
    for group in activity_groups:
        if group.subcluster not in subcluster_dict.keys():
            subcluster_dict[group.subcluster] = [group]
        else:
            subcluster_dict[group.subcluster] += [group]
    for entry in subcluster_dict.keys():
        # if entry == -1:
        #    continue  # skip the unclustered_group
        earliest = subcluster_dict[entry][0].first_seen_in_this_group
        latest = subcluster_dict[entry][-1].first_seen_in_this_group
        interval_start_time = int(earliest)
        if interval_start_time not in collection_dict:
            collection_dict[interval_start_time] = []
        collection_dict[interval_start_time] += [dict({"destBytes": 0, "totalFlows": 0})]
        logger.info("Inspecting subcluster " + str(entry))
        for g in subcluster_dict[entry]:
            logger.info("\t" + str(g.destination_and_port) + " starting at " + str(g.first_seen_in_this_group))
            collection_dict[interval_start_time][-1]["totalFlows"] += len(g.overlapping_activities)
            if g.destination_and_port in collection_dict[interval_start_time][-1].keys():
                collection_dict[interval_start_time][-1][g.destination_and_port] += (
                    len(g.overlapping_activities), g.first_seen_in_this_group)
            else:
                collection_dict[interval_start_time][-1][g.destination_and_port] = (
                    len(g.overlapping_activities), g.first_seen_in_this_group)
            for activity in g.overlapping_activities:
                collection_dict[interval_start_time][-1]["destBytes"] += int(activity["secflow"]["destinationBytes"])
        if collection_dict[interval_start_time][-1]["totalFlows"] < 3 or int(
                collection_dict[interval_start_time][-1]["destBytes"]) < 200000:
            # logger.info("Throwing away subcluster because destbytes (" + str(collection_dict[interval_start_time][-1]["destBytes"]) + ") < 200K")
            collection_dict[interval_start_time].pop(-1)  # throw it away
    return collection_dict


def setup_inference_objects_by_category(category, bucketed_activities, all_incoming_activities, activity_groups,
                                        unknown_destinations=None):
    """Even though we don't actually collect inferences for all categories, we should set them up for all categories so
        that if we need their info we can grab it.
    """
    # collect unique SUSPICIOUS destinations
    unique_destinations = set()
    if activity_groups != []:
        for group in activity_groups:
            if group.category == category:
                unique_destinations.add(group.destination_and_port)
    else:  # we have no activities
        if unknown_destinations is not None:  # we also have unknown destinations, which means it's likely a destination analysis
            for dest in unknown_destinations:
                unique_destinations.add(dest)
    logger.info(str(len(unique_destinations))
                 + " unique "
                 + category
                 + " destinations in sample: "
                 )
    for d in unique_destinations:
        logger.info("\t" + str(d))
    destinations_with_inferences = dict()
    for destination in unique_destinations:
        # collect all activities that are associated with that destination
        acts_for_dest = []
        for activity in all_incoming_activities:
            if activity["secflow"]["destinationData"] == destination:
                acts_for_dest += [activity]
        buckets_for_dest = []  # all bucketed activities for this destination, when that's useful
        for bucket in bucketed_activities:
            for entry in bucket:
                if bucket[entry]["destinationData"] == destination:
                    buckets_for_dest += [bucket[entry]]
        if destination in destinations_with_inferences.keys():
            inference_object = destinations_with_inferences[destination]
            # update activities and buckets, since we didn't have them earlier
            inference_object.activities_list = acts_for_dest
            inference_object.my_buckets = buckets_for_dest
            inference_object.set_first_last_times()
        else:
            destinations_with_inferences[destination] = inference_collector.InferenceCollector(destination
                                                                                               , acts_for_dest
                                                                                               , buckets_for_dest
                                                                                               , category
                                                                                               )
    return destinations_with_inferences


def collect_inferences(all_incoming_activities, bucketed_activities, activity_groups, known_activities, api_key,
                       unknown_destinations=None):
    """Takes a list of all incoming activities, all bucketed activities for the sample (see bucketing function above)
        and all activity groups (a list of ActivityGroup objects) and identifies which Inferences are associated with
        which destinations by creating an InferenceCollector object for Suspicious Activity destinations only. For
        analyses that are JUST on destinations (and not activities), this information is passed in and correctly handled
        using the unknown_destinations variable.
    """
    all_inference_objects = {"suspicious":
                                 setup_inference_objects_by_category("Suspicious Activity"
                                                                     , bucketed_activities
                                                                     , all_incoming_activities
                                                                     , activity_groups
                                                                     , unknown_destinations
                                                                     )
        , "malicious": setup_inference_objects_by_category("Malicious Activity"
                                                           , bucketed_activities
                                                           , all_incoming_activities
                                                           , activity_groups
                                                           )
        , "attack_vector": setup_inference_objects_by_category("Attack Vector"
                                                               , bucketed_activities
                                                               , all_incoming_activities
                                                               , activity_groups
                                                               )
        , "impact": setup_inference_objects_by_category("Impact"
                                                        , bucketed_activities
                                                        , all_incoming_activities
                                                        , activity_groups
                                                        )
        , "common": setup_inference_objects_by_category("Common Activity"
                                                        , bucketed_activities
                                                        , all_incoming_activities
                                                        , activity_groups
                                                        )
                             }
    # prep some related topics
    cluster_activity(activity_groups)
    ordered_clusters = get_clusters_by_start_time(activity_groups)
    get_subclusters(activity_groups, ordered_clusters=ordered_clusters)

    # perform sample-global inferences first
    is_pageload_behavior(all_incoming_activities
                         , bucketed_activities
                         , all_inference_objects
                         , ordered_clusters
                         , activity_groups
                         )
    find_extension_installation(activity_groups)

    for category in all_inference_objects.keys():
        if category not in ["suspicious", "malicious"]:  # only compute for these categories today
            for destination in all_inference_objects[category].keys():
                # We need to check other, known, destinations for certain categories, because they need more analysis.
                if not is_built_on_trusted(all_inference_objects[category][destination], known_activities, api_key):
                    continue
                else:
                    # move to Suspicious Activity category
                    all_inference_objects[category][destination].category = "Suspicious Activity"
        for destination in all_inference_objects[category].keys():
            inference_object = all_inference_objects[category][destination]
            if not has_likely_c2(inference_object, activity_groups):
                if not has_other_interesting(activity_groups):
                    continue  # this one more or less excludes the rest
                else:
                    try:
                        del inference_object.associated_inferences["unlikely_c2"]
                    except:
                        logger.info("Deleting unlikely_c2 inference failed.")
            has_significant_session_count(inference_object)
            has_uncommon_ip_address(inference_object)
            has_uncommon_ports(inference_object)
            has_repeated_activity(inference_object)
            has_large_transactions(inference_object)
            has_file_or_app_download(inference_object)
            has_suspicious_dns_flows(inference_object)
            if "actual_page_loaded" in inference_object.associated_inferences.keys():
                has_autofill_form(inference_object, known_activities)
            # print("Checking built on trusted for", inference_object.destination_and_port)
            is_built_on_trusted(inference_object
                                , known_activities
                                , api_key
                                )
            if "built_on_trusted" in inference_object.associated_inferences:
                logging.info(str(destination) + " is built on trusted!")
            is_browsed_site(inference_object)
            is_associated_with_authentication(inference_object
                                              , bucketed_activities
                                              , activity_groups
                                              )
            # is_caused_by_or_causing_seen_near_bad(inference_object, bucketed_activities, activity_groups)
            # keep going through all of the Inferences
    for category in all_inference_objects.keys():
        logger.info("Inferences for destinations with activity in category "
                     + category
                     + ":"
                     )
        for destination in all_inference_objects[category].keys():
            if len(all_inference_objects[category][destination].associated_inferences) == 0:
                continue
            logger.info("\t" + all_inference_objects[category][destination].get_title() + "\n\t\tInferences:")
            for inference_title in all_inference_objects[category][destination].associated_inferences.keys():
                logger.info("\t\t"
                             + str(inference_title)
                             + " --> "
                             + str(all_inference_objects[category][destination].associated_inferences[inference_title])
                             + "\n"
                             )
    return all_inference_objects


# ------------------------------------- Begin actual Inferences ------------------------------------

def has_suspicious_dns_flows(inference_object):
    """Suspicious sites with non dnsQuery traffic on well-known DNS ports are interesting. This can help to detect
        certain types of attacks, such as DNS exfiltration or using DNS as a C2 tunnel.
    """
    if ":53" not in inference_object.destination_and_port:
        return False
    for act in inference_object.activities_list:
        if act["secflow"]["flowCategory"] != "dnsQuery":
            inference_object.associated_inferences["suspicious dns flows"] = (
                "Suspicious sites with non dnsQuery traffic on well-known DNS ports are interesting. This can help to detect certain types of attacks, such as DNS exfiltration or using DNS as a C2 tunnel."
                , 1
            )
            return True


def has_likely_c2(inference_object, activity_groups):
    """Suspicious sites acting in a C2-like manner, but with no more than 50 bytes in either direction is not a
        significant amount of data to accomplish anything meaningful, and weeds out a significant number of connections
        that were mostly dormant and uninteresting (but not well-identified, since they may’ve had no DNS naming) in a
        sample. Those that have at least 1KB in either direction, however, will be marked as likely C2.
    """
    total_bytes_sent = 0
    total_bytes_received = 0
    for act in inference_object.activities_list:
        if act["secflow"]["flowCategory"] == "asNeededChannel":
            total_bytes_sent += int(act["secflow"]["sourceBytes"])
            total_bytes_received += int(act["secflow"]["destinationBytes"])
    if total_bytes_sent == 0 and total_bytes_received == 0:
        return True  # we didn't actually see this flow category for this dest
    if total_bytes_sent >= 1024 or total_bytes_received >= 1024:
        inference_object.associated_inferences["likely_c2"] = (
            "A C2-like channel exists and has sent at least 1KB, which is an amount great enough to arouse suspicion."
            , 2
        )
    elif total_bytes_sent <= 50 or total_bytes_received < 50:
        inference_object.associated_inferences["unlikely_c2"] = (
            "Fewer than 50 bytes were sent or recieved in a back-and-forth way. It is likely that this is actually a dormant session that existed before this sample began."
            , -10
        )
        return False
    return True


def has_significant_session_count(inference_object):
    """The number of sessions in a sample for a given destination can help us to understand whether it's potentially an
        important part of the sample.
    """
    num_sessions = len(inference_object.activities_list)
    if num_sessions >= 5:
        inference_object.associated_inferences["five_plus_sessions"] = (
            "There are at least 5 sessions to this destination. This could mean that this destination is important in this sample."
            , 3
        )
        return True  # only want to capture one of these
    if num_sessions >= 2:
        inference_object.associated_inferences["two_plus_sessions"] = (
            "There are at least 2 sessions to this destination."
            , 3
        )
    return True


def has_large_transactions(inference_object):
    """When we see a large amount of data going up or down to a site, that becomes more interesting. Only certain flow
        categories are inspected for either direction of data flow.
    """

    download_flow_categories = ["unclassified"
        , "continuousServerChannel"
        , "unidirectional"
        , "minorContentDownloadedQuickly"
        , "someContentDownloadedQuickly"
        , "majorContentDownloadedQuickly"
        , "minorResourcesDownloadedQuickly"
        , "someResourcesDownloadedQuickly"
        , "majorResourcesDownloadedQuickly"
        , "minorContentDownloaded"
        , "someContentDownloaded"
        , "majorContentDownloaded"
        , "minorResourcesDownloaded"
        , "someResourcesDownloaded"
        , "majorResourcesDownloaded"
        , "minorDataDownloadedViaLongSession"
        , "someDataDownloadedViaLongSession"
        , "majorDataDownloadedViaLongSession"
        , "singleResourceLoaded"
                                ]
    upload_flow_categories = ["largeUpload"
        , "smallUpload"
        , "unclassified"
        , "continuousClientChannel"
        , "unidirectional"
        , "singleResourceLoaded"
                              ]
    total_bytes_sent = 0
    total_bytes_received = 0
    for activity in inference_object.activities_list:
        if activity["secflow"]["flowCategory"] in upload_flow_categories:
            total_bytes_sent += int(activity["secflow"]["sourceBytes"])
        if activity["secflow"]["flowCategory"] in download_flow_categories:
            total_bytes_received += int(activity["secflow"]["destinationBytes"])
    if total_bytes_sent >= 1048576:
        inference_object.associated_inferences["large_upload"] = (
            "At least 1 MB has been uploaded to this destination. As this number increases, it becomes more likely that this is something of interest (for example, as data exfiltration)."
            , 5
        )
    if total_bytes_received >= 1048576:
        inference_object.associated_inferences["large_download"] = (
            "At least 1 MB has been downloaded from this destination. As this number increases, it becomes more likely that this is a download of significant raw data, a document, or an application. This likely warrants more attention."
            , 3
        )
    return True


def has_file_or_app_download(inference_object):
    """When we see a large amount of data coming down from a site in a fast (relative to its size) manner, this becomes
        even more interesting. It may indicate that a program or very large file (such as a PDF) is being downloaded.
    """

    download_flow_categories = ["majorContentDownloadedQuickly"
        , "majorContentDownloaded"
        ]
    long_download = "majorDataDownloadedViaLongSession"
    total_bytes_received = 0
    long_download_bytes = 0
    activity_duration = 0.0
    for activity in inference_object.activities_list:
        if activity["secflow"]["flowCategory"] in download_flow_categories:
            total_bytes_received += int(activity["secflow"]["destinationBytes"])
        elif activity["secflow"]["flowCategory"] == long_download:
            long_download_bytes += int(activity["secflow"]["destinationBytes"])
            activity_duration += float(activity["secflow"]["duration"])
    long_bytes = utilities.convert_size(long_download_bytes)
    other_download_bytes = utilities.convert_size(total_bytes_received)
    if long_bytes == "0B" or ("MB" in long_bytes and long_download_bytes < 100000000):
        pass
    else:
        inference_object.associated_inferences["large_fileapp_download"] = (
            long_bytes
            + " was downloaded from this destination. Usually that amount of data is associated with "
            + " an application being downloaded. If this is occurring from an unexpected site, it could be malicious."
            , 1
        )
    if other_download_bytes == "0B":  # this shouldn't be possible
        pass
    else:
        inference_object.associated_inferences["fileapp_download"] = (
            other_download_bytes
            + " was downloaded from this destination in a very short amount of time. This increases the chance that this"
            + " is a download to look into, especially if the site is not well-known or is nearby other Suspicious or "
            + "Malicious activity. "
            , 5
        )
    return True


def has_uncommon_ip_address(inference_object):
    """Suspicious sites that are also IP addresses are more interesting.
    """
    dest = inference_object.destination_and_port[:inference_object.destination_and_port.rfind(":")]
    try:
        if ipaddress.ip_address(dest):
            if "unlikely_c2" in inference_object.associated_inferences.keys():
                return False
            inference_object.associated_inferences["uncommon_ip"] = (
                "This site is an IP address, which is more commonly seen when an attacker wants to quickly set up infrastructure and avoid registering a domain name."
                , 1
            )
            return True
    except:
        return False
    return False


def has_uncommon_ports(inference_object):
    """Suspicious sites with uncommon ports are interesting.
    """
    port = inference_object.destination_and_port[inference_object.destination_and_port.rfind(":") + 1:]
    if port not in common_ports:
        inference_object.associated_inferences["uncommon_port"] = (
            "This site is communicated with on a port that is not commonly seen."
            , 1
        )
        return True
    return False


def has_repeated_activity(inference_object):
    """Suspicious sites with certain kinds of repeated activities are interesting.
    """
    repeated = False
    for bucket in inference_object.my_buckets:
        if bucket["flowCategory"] == "smallUpload" and len(bucket["activities"]) >= 3:
            # if there are 3 smallUpload activities for a destination in ONE bucket, capture it.
            inference_object.associated_inferences["repeated_uploads"] = (
                "In a short period of time, there were several quick uploads to this site, which is unusual."
                , 3
            )
            repeated = True
            break  # we only need to find one
    # if there are 5+ unclassified activities to this destination across the whole file, capture it
    unclassified_count = 0
    for bucket in inference_object.my_buckets:
        if bucket["flowCategory"] == "unclassified":
            unclassified_count += len(bucket["activities"])
    if unclassified_count >= 5:
        inference_object.associated_inferences["repeated_unclassified"] = (
            "In this sample, there were "
            + str(unclassified_count)
            + " unclassified activities to this site. This is unusual."
            , 1
        )
        repeated = True
    return repeated


def has_autofill_form(inference_object, known_activities):
    """When we have a site that we believe to be the page loaded, determine if it has an Autofill form loading. If it
        does, this increases our interest in it more.
    """
    for bucket in inference_object.my_buckets:
        for known in known_activities:
            if (float(known["secflow"]["relativeStart"]) >= float(bucket["minRelativeStart"])
                    and (float(bucket["minRelativeStart"]) + interval_duration) >= float(
                        known["secflow"]["relativeStart"])
            ):  # tighten the time range
                if ("destination" in known.keys()
                        and len(known["destination"]) > 0
                        and "Autofill Form" in known["destination"]["title"]
                ):
                    inference_object.associated_inferences["has_autofill_form"] = (
                        "Based on the activity in this sample, it looks as though this site also has a form loading. This could be a form asking for credentials, for address and payment information, or for some other data that the user is expected to input."
                        , 1
                    )
                    return True  # we only need one


def is_built_on_trusted(inference_object, known_activities, api_key):
    """Sites that are built on top of trusted file-sharing sites are extra interesting, as they hide from a lot of the
        analysis (WHOIS, reputation, etc...) that is commonly done on domains. We'll actually use this to identify one
        of two interesting cases. The first is when the Destination/Behavior is built on trusted and labeled only in the
        destinationTags metadata. In that case, we don't know much about whether it was an Attack Vector or (for
        example) a phishing portal. The second case is when the Destination/Behavior contains metadata in the
        attackVectorTags metadata. That tells us more specifically how something is used.
    """
    should_check = False
    dest = inference_object.destination_and_port
    try:
        if ipaddress.ip_address(dest[:dest.rfind(":")]):
            return False
    except:
        pass
    for bucket in inference_object.my_buckets:
        if "Download" in bucket["flowCategory"]:
            should_check = True
            break  # only need to see this once
    if not should_check:
        if inference_object.my_buckets != []:  # destination analysis mode won't have any buckets
            return False
    # figure out base domain
    try:
        dchunks = dest.split(":")
        name = dchunks[0]
        try:
            port = dchunks[1]
            if port not in common_ports:
                logger.info("For lookup in sample and DB, using port 443 in place of uncommon port " + str(port))
                port = "443"
        except:
            logger.warning("Failed to find a port...defaulting to 443")
            port = "443"
    except:
        logger.warning("Split failed, maybe an issue with destination name " + str(dest))
        name = dest  # fall back to assigning to original destination
        port = "443"  # fall back to default
    chunks = name.split(".")
    match = None
    """If the name of the destination is at least 3 names long (i.e. "untrusted.web.app"), check to see if we know
        anything about the underlying destinations.
    """
    if len(chunks) > 2:
        dest_to_check_len2 = ".".join(chunks[-2:]) + ":" + port  # last 2
        try:
            dest_to_check_len3 = ".".join(chunks[-3:]) + ":" + port  # last 3
        except:
            dest_to_check_len3 = ""
        for known in known_activities:
            if known["secflow"]["destinationData"] in [dest_to_check_len2, dest_to_check_len3]:
                if dest == dest_to_check_len2:
                    match = known
                    #logger.info("We found a match of length 2 with " + dest)
                    break
                if dest == dest_to_check_len3:
                    match = known
                    #logger.info("We found a match of length 3 with " + dest)
                    break
    else:
        return False
    # vars to make the code below cleaner
    prefix = "This site was built on top of a trusted file-sharing site ("
    suffix_unknown = "). This is interesting, as it is a tactic to quickly and easily build a site that hides from a lot of the analysis (WHOIS, reputation, etc...) that is commonly done on domains."
    suffix_av = "). Moreover, the underlying Destination is most commonly seen as an Attack Vector where attacks begin."
    if "actual_page_loaded" in inference_object.associated_inferences:
        score = 5
    elif "page_resources_loaded" in inference_object.associated_inferences:
        score = 2
    else:
        score = 0  # no-op because we don't think this will actually be interesting in this sample.
    if match is not None:
        answer = None
        """Check the data we've already collected for this sample first to avoid taxing the database. We need to check
            two tag places in both Destinations and Behaviors, any of which may not exist as a field.
        """
        try:  # Attack Vector more likely
            if ("CloudHostingPlatform" in match["destination"]["attackVectorTags"]
                    or "FileSharingPlatform" in match["destination"]["attackVectorTags"]
            ):
                answer = match["destination"]["title"]
                inference_object.associated_inferences["likely_attackvector"] = (prefix
                                                                                 + answer
                                                                                 + suffix_av
                                                                                 , score
                                                                                 )
                return True
        except:
            try:
                if ("CloudHostingPlatform" in match["behavior"]["attackVectorTags"]
                        or "FileSharingPlatform" in match["behavior"]["attackVectorTags"]
                ):
                    answer = match["behavior"]["title"]
                    inference_object.associated_inferences["likely_attackvector"] = (prefix
                                                                                     + answer
                                                                                     + suffix_av
                                                                                     , score
                                                                                     )
                    return True
            except:
                pass
        try:  # unsure how it's used
            #logging.info("Checking Destination's destinationTags")
            if ("CloudHostingPlatform" in match["destination"]["destinationTags"]
                    or "FileSharingPlatform" in match["destination"]["destinationTags"]
            ):
                answer = match["destination"]["title"]
                inference_object.associated_inferences["built_on_trusted"] = (prefix
                                                                              + answer
                                                                              + suffix_unknown
                                                                              , score
                                                                              )
                return True
        except:
            try:
                if ("CloudHostingPlatform" in match["behavior"]["destinationTags"]
                        or "FileSharingPlatform" in match["behavior"]["destinationTags"]
                ):
                    answer = match["behavior"]["title"]
                    inference_object.associated_inferences["built_on_trusted"] = (prefix
                                                                                  + answer
                                                                                  + suffix_unknown
                                                                                  , score
                                                                                  )
                    return True
            except:
                pass
    else:  # check our database
        result_len2 = retrieve_metadata.get_metadata_for_item("destination", dest_to_check_len2, api_key)
        result_len3 = retrieve_metadata.get_metadata_for_item("destination", dest_to_check_len3, api_key)
        if result_len2 == {} and result_len3 == {}:
            return False
        # We know we have metadata for at least some of the Destinations or Behaviors, so now check the same way as above.
        if result_len2 != {}:
            try:
                attackVectorTags = json.loads(result_len2["attackVectorTags"])
                if ("CloudHostingPlatform" in attackVectorTags
                        or "FileSharingPlatform" in attackVectorTags
                ):
                    answer = result_len2["title"]
                    inference_object.associated_inferences["likely_attackvector"] = (prefix
                                                                                     + answer
                                                                                     + suffix_av
                                                                                     , score
                                                                                     )
                    return True
            except:
                try:
                    destinationTags = json.loads(result_len2["destinationTags"])
                    if ("CloudHostingPlatform" in destinationTags
                            or "FileSharingPlatform" in destinationTags
                    ):
                        answer = result_len2["title"]
                        inference_object.associated_inferences["built_on_trusted"] = (prefix
                                                                                      + answer
                                                                                      + suffix_unknown
                                                                                      , score
                                                                                      )
                        return True
                except:
                    pass
        if result_len3 != {}:
            try:
                attackVectorTags = json.loads(result_len3["attackVectorTags"])
                if ("CloudHostingPlatform" in attackVectorTags
                        or "FileSharingPlatform" in attackVectorTags
                ):
                    answer = result_len3["title"]
                    inference_object.associated_inferences["likely_attackvector"] = (prefix
                                                                                     + answer
                                                                                     + suffix_av
                                                                                     , score
                                                                                     )
                    return True
            except:
                try:
                    destinationTags = json.loads(result_len3["destinationTags"])
                    if ("CloudHostingPlatform" in destinationTags
                            or "FileSharingPlatform" in destinationTags
                    ):
                        answer = result_len3["title"]
                        inference_object.associated_inferences["built_on_trusted"] = (prefix
                                                                                      + answer
                                                                                      + suffix_unknown
                                                                                      , score
                                                                                      )
                        return True
                except:
                    pass
    return False


def is_browsed_site(inference_object):
    """Suspicious sites that seem to have been browsed (download behavior spanning more than one 15 second window) are
        useful to track.
    """
    other_download_flow_categories = ["minorContentDownloadedQuickly"
        , "someContentDownloadedQuickly"
        , "majorContentDownloadedQuickly"
        , "minorResourcesDownloadedQuickly"
        , "someResourcesDownloadedQuickly"
        , "majorResourcesDownloadedQuickly"
        , "minorContentDownloaded"
        , "someContentDownloaded"
        , "majorContentDownloaded"
        , "minorResourcesDownloaded"
        , "someResourcesDownloaded"
        , "majorResourcesDownloaded"
                                      ]
    long_download_flow_categories = ["minorDataDownloadedViaLongSession"
        , "someDataDownloadedViaLongSession"
        , "majorDataDownloadedViaLongSession"
                                     ]
    # if there are 3 smallUpload activities for a destination in ONE bucket, capture it.
    earliest_time = -1
    latest_time = 0
    for bucket in inference_object.my_buckets:
        if bucket["flowCategory"] in (long_download_flow_categories + other_download_flow_categories):
            if earliest_time == -1:
                earliest_time = float(bucket["minRelativeStart"])  # set first time only
            for activity in bucket["activities"]:
                latest_time = max(float(activity["secflow"]["relativeStart"]) + float(activity["secflow"]["duration"]),
                                  latest_time)
                if latest_time - earliest_time > 15:
                    if ("actual_page_loaded" in inference_object.associated_inferences
                            or "large_download" in inference_object.associated_inferences
                    ):
                        inference_object.associated_inferences["likely_browsed_site"] = (
                            "This site was active for a relatively long period of time. This could mean that someone was browsing the site, or it may indicate a connection that is continuously loading something in the background."
                            , 3
                        )
                    else:
                        inference_object.associated_inferences["likely_background_behavior"] = (
                            "This site was active for a relatively long period of time, but it didn't seem to be something that a user actively interacted with. This could mean that it is background activity on a site (such as tracking, analytics, or assets loading), or is some operating system functionality."
                            , 0
                        )
                    return True  # we only need to find one


def is_pageload_behavior(all_incoming_activities, bucketed_activities, all_inference_objects, ordered_clusters,
                         activity_groups):
    """Allows us to track activity what very likely is occurring because a page just loaded. Logic:
        1. Collect buckets of the original buckets (this information already does step #2 below)
        2. If there are consecutive buckets (i.e. one starts at 35 seconds and the next starts at 40 seconds) and there
            isn’t any indication (through other labeled activity, such as a “New Tab loaded in Google”) that they are
            separate, combine them and update any values (counts, sums).
        3. For each flow to a particular destination in the sample, if the earliest start time we’ve seen for it (in
            this sample) is in one of the remaining buckets, label it as part of a pageload (this is oversimplified and
            will need more exclusions from some of the other inferences we’ve seen above).
        4. Finally, label the destination whose count is highest in a pageload bucket as the site being loaded, as long
           as it's convincing.
    """

    resource_load_tags = ["LogoStorage"
        , "WebsiteLoading"
        , "Ads"
        , "Tracking"
        , "Assets"
                          ]
    pl_desc = "Activity to this site occurs in a brief period of this sample where we believe a new website or page is being loaded. Moreover, the traffic from this site leads us to believe that it was the site that was actually loaded (for example, through a link click). This could be more interesting."
    resl_desc = "Activity to this site occurs in a brief period of this sample where we believe a new website or page is being loaded, but we believe that these are resources being loaded to support a page."
    # step 1 (using data that already implements step 2)
    meta_buckets = collect_meta_buckets(activity_groups)
    if len(meta_buckets) == 0:
        return False
    # step 2.5 -- capture different aspects of a page load
    for interval in meta_buckets.keys():
        """Entries here are sorted (ascending) by the earliest time they were seen in this particular period (second
            item in each tuple). So let's use that to identify the most likely loaded page.
        """
        count = 0
        load_found = False
        for cluster in meta_buckets[interval]:
            for item in cluster.keys():
                if item in ["destBytes", "totalFlows"]:
                    continue  # skip these for now
                dest_groups = activity_grouping.get_activity_groups_for_destination(item, activity_groups)
                inference_object = get_object(item, all_inference_objects)
                if inference_object is None:
                    # couldn't find an inference object for the destination object, so skip
                    continue
                has_interesting = False
                relevant_group = None
                for group in dest_groups:
                    if group.first_seen_in_this_group == cluster[item][1]:
                        relevant_group = group
                        break
                if relevant_group is None:
                    logger.info("Couldn't find activity group for "
                                 + item
                                 + ". Skipping."
                                 )
                    continue
                highest_metadata = activity_grouping.get_highest_metadata_for_group(relevant_group)
                metadata_used = False
                inference_length = len(inference_object.associated_inferences)
                if highest_metadata is not None:
                    # work with known metadata first
                    logger.info("We have the following metadata for this activity group of "
                                 + relevant_group.destination_and_port
                                 )
                    for m in highest_metadata.keys():
                        logger.info("\t"
                                     + m
                                     + " --> "
                                     + str(highest_metadata[m])
                                     )
                    try:
                        ap_tags = ast.literal_eval(highest_metadata["activityPurposeTags"])
                        if "Redirect" in ap_tags:
                            inference_object.associated_inferences["is_redirect"] = (
                                "We are relatively sure that this is REDIRECT behavior, but we haven't pulled it into our logic yet!"
                                , 0
                            )
                        if any(tag in ap_tags for tag in resource_load_tags):
                            inference_object.associated_inferences["page_resources_loaded"] = (
                                resl_desc
                                , 1
                            )
                        if "UI" in ap_tags:
                            inference_object.associated_inferences["actual_page_loaded"] = (
                                pl_desc
                                , 3
                            )
                        if "Redirect" in ap_tags:
                            inference_object.associated_inferences["is_redirect"] = (
                                "We are relatively sure that this is REDIRECT behavior, but we haven't pulled it into our logic yet!"
                                , 0
                            )
                    except:
                        pass
                    try:
                        dest_tags = ast.literal_eval(highest_metadata["destinationTags"])
                        if "URLShortener" in dest_tags:
                            inference_object.associated_inferences["suspected_attack_vector"] = (
                                "We are relatively sure that this is an attack vector, but we haven't pulled it into our logic yet!"
                                , 0
                            )
                        elif "UpdateServers" in dest_tags:
                            inference_object.associated_inferences["update_activity"] = (
                                "This is update activity that is likely unrelated to any page load."
                                , -1
                            )
                    except:
                        pass
                    try:
                        relevance = highest_metadata["relevance"]
                        if "seenNearBad" in relevance:
                            inference_object.associated_inferences["page_resources_loaded"] = (
                                resl_desc + " In this case, we know that this activity is often seen near bad activity."
                                , 1
                            )
                        elif "knownBad" in relevance:
                            inference_object.associated_inferences["page_resources_loaded"] = (
                                resl_desc + " In this case, we know that this activity is malicious!"
                                , 10
                            )
                    except:
                        pass
                if inference_length < len(inference_object.associated_inferences):
                    metadata_used = True  # we'll want to do other things here, potentially
                for activity in relevant_group.overlapping_activities:
                    if activity["secflow"]["flowCategory"].startswith("some") or activity["secflow"][
                        "flowCategory"].startswith("major"):
                        has_interesting = True
                        # logger.info("Potential candidate for pageload: " + relevant_group.destination_and_port + ", which is in subcluster " + str(relevant_group.subcluster))
                if count == 0:  # first real destination
                    if "update_activity" in inference_object.associated_inferences:
                        logger.info(str(item) + " is just update behavior")
                        inference_object.associated_inferences["update_activity"] = (
                            "This is update activity that is likely unrelated to any page load."
                            , -1
                        )
                    elif has_interesting:
                        logger.info("We're thinking " + str(item) + " is the actual page loaded")
                        inference_object.associated_inferences["actual_page_loaded"] = (
                            pl_desc
                            , 3
                        )
                        load_found = True
                    else:
                        logger.info(str(item) + " may be background behavior during a page load")
                elif count > 0:
                    if has_interesting and not load_found and not "update_activity" in inference_object.associated_inferences:
                        inference_object.associated_inferences["actual_page_loaded"] = (
                            pl_desc
                            , 3
                        )
                        logger.info("Maybe " + str(item) + " is the actual page loaded...")
                        load_found = True
                    else:
                        logger.info(str(item) + " is probably background or resource load behavior...")
                count += 1


def find_extension_installation(activity_groups):
    """Takes all of the known activities and attempts to discover if any of them are known to be involved with any sort
        of browser extension installation. If so, we update the category.
    """
    for g in activity_groups:
        if g.has_known_metadata:
            metadata = activity_grouping.get_highest_metadata_for_group(g)
            if "Chrome Extension" in metadata["title"]:  # TODO: this should be captured in tags!
                my_groups = activity_grouping.get_activity_groups_for_destination(g.destination_and_port,
                                                                                  activity_groups
                                                                                  )
                activity_grouping.relabel_category_for_destination(my_groups, "Impact", "Medium-High")


def collect_interesting_subclusters(interesting_clusters, ordered_clusters):
    """Takes the list of interesting clusters and returns subclusters which are also interesting.
    """
    interesting_subclusters = set()
    for cluster in interesting_clusters:
        for g in ordered_clusters[cluster]:
            interesting_subclusters.add(g.subcluster)
    return interesting_subclusters


def collect_root_domains_and_orgs(g, excluded_domains, excluded_orgs, dest_evidence, dest_sans_port, suspected_phishing,
                                  root_domains, orgs):
    """This logic analyzes a particular destination (without its port) and determines if it should be considered for the
        topic of this sample. It attempts to find the most contextually-relevant thing, such as the organization name.
    """
    topic = None
    skip = False
    if dest_sans_port in excluded_domains:
        skip = True
        return (root_domains, orgs, topic, skip)
    try:
        if "actual_page_loaded" in dest_evidence["inferences"].associated_inferences and g.category not in [
            "Suspicious Activity", "Malicious Activity"]:
            # print("Trying to get brand-specific topic from", dest_evidence["org_by_whois"])
            try:
                if type(dest_evidence["org_by_whois"]) == list:
                    topic = ("brand", dest_evidence["org_by_whois"][0])
                else:
                    topic = ("brand", dest_evidence["org_by_whois"])
            except:
                topic = ("generic", dest_sans_port)
            if topic[1] != None:
                logger.info("Short-circuiting logic because we think we found the topic: "
                             + str(topic)
                             )
                if topic in org_hiding_registrars or re.findall(org_hiding_registrars_regex, topic):
                    topic = None
                    skip = True
                elif topic in excluded_domains or topic in excluded_orgs:
                    topic = None
                    skip = True
            else:
                topic = ("generic", dest_sans_port)
            return (root_domains, orgs, topic, skip)
    except:
        pass
    if "root_domain_by_whois" not in dest_evidence.keys():
        root_domain = dest_sans_port  # use the actual destination as fall-back
    else:
        try:
            root_domain = dest_evidence["root_domain_by_whois"].lower()  # when it's a string
        except:
            try:
                root_domain = dest_evidence["root_domain_by_whois"][0].lower()  # when it's a list
            except:
                # print("Couldn't find root domain in", verdict["destinations"][dest_sans_port])
                skip = True
                return (root_domains, orgs, topic, skip)
    try:
        if type(dest_evidence["org_by_whois"]) == list:
            org = dest_evidence["org_by_whois"][0]
        else:
            org = dest_evidence["org_by_whois"]
    except:
        org = None
    if dest_sans_port in suspected_phishing:
        skip = True
        return (root_domains, orgs, topic, skip)
    if root_domain is not None:
        if root_domain in root_domains.keys():
            root_domains[root_domain] += len(g.overlapping_activities)
        else:
            root_domains[root_domain] = len(g.overlapping_activities)
    if org is not None:
        if org in orgs.keys():
            orgs[org] += len(g.overlapping_activities)
        else:
            orgs[org] = len(g.overlapping_activities)
    return (root_domains, orgs, topic, skip)


def get_most_likely_topic(root_domains_by_cluster, root_domains_by_subcluster, orgs_by_cluster, orgs_by_subcluster):
    """This logic analyzes all of the collected root domains and orgs (from WHOIS) for all of the interesting clusters
        and subclusters, and determines which one occurs the most. Filters out things that don't make sense.
    """
    max_count_root_domains = ("", 0)
    max_count_orgs = ("", 0)
    # print("Root domains by cluster:", root_domains_by_cluster)
    # print("Root domains by subcluster:", root_domains_by_subcluster)
    # print("Orgs by cluster:", orgs_by_cluster)
    # print("Orgs by subcluster:", orgs_by_subcluster)
    for cluster in root_domains_by_cluster.keys():
        # print("CLUSTER", cluster, "has the following root domains count:", root_domains_by_cluster[cluster])
        for root in root_domains_by_cluster[cluster]:
            if root_domains_by_cluster[cluster][root] > max_count_root_domains[1]:
                max_count_root_domains = (root, root_domains_by_cluster[cluster][root])
    for subcluster in root_domains_by_subcluster.keys():
        # print("SUBcluster", subcluster, "has the following root domains count:", root_domains_by_subcluster[subcluster])
        for root in root_domains_by_subcluster[subcluster]:
            if root_domains_by_subcluster[subcluster][root] > max_count_root_domains[1]:
                max_count_root_domains = (root, root_domains_by_subcluster[subcluster][root])
    for cluster in orgs_by_cluster.keys():
        # print("CLUSTER", cluster, "has the following Orgs count:", orgs_by_cluster[cluster])
        for org in orgs_by_cluster[cluster]:
            if org is None or org in org_hiding_registrars or re.findall(org_hiding_registrars_regex, org):
                continue
            if orgs_by_cluster[cluster][org] > max_count_orgs[1]:
                max_count_orgs = (org, orgs_by_cluster[cluster][org])
    for subcluster in orgs_by_subcluster.keys():
        # print("SUBcluster", subcluster, "has the following Orgs count:", orgs_by_subcluster[subcluster])
        for org in orgs_by_subcluster[subcluster]:
            if org is None or org in org_hiding_registrars or re.findall(org_hiding_registrars_regex, org):
                continue
            if orgs_by_subcluster[subcluster][org] > max_count_orgs[1]:
                max_count_orgs = (org, orgs_by_subcluster[subcluster][org])
    logger.info("Max of root domains: "
                 + str(max_count_root_domains[1])
                 + " for "
                 + max_count_root_domains[0]
                 )
    logger.info("Max of Orgs: "
                 + str(max_count_orgs[1])
                 + " for "
                 + max_count_orgs[0]
                 )
    if max_count_root_domains[1] < 2 and max_count_orgs[1] < 2:
        logger.info("Ignoring topic data because count is low.")
        topic = None
    elif max_count_root_domains[1] > max_count_orgs[1]:
        logger.info("Capturing generic topic of " + str(max_count_root_domains[0]))
        topic = ("generic", max_count_root_domains[0])  # harder to figure out if brand or not, here
    else:  # a tie or greater defaults to using the org, which (when it's a real org) provides clearer info for user
        logger.info("Capturing brand topic of " + str(max_count_orgs[0]))
        topic = ("brand", max_count_orgs[0])
    return topic


def discover_topic(ordered_clusters, interesting_clusters, interesting_subclusters, verdict, activity_groups,
                   discovered_destination_purposes=None):
    """This Inference is an advanced one that first requires all of the preliminary knowledge about a sample to be
        completed. It uses Inferences plus interesting clusters of activity to determine follow-on details about which
        topic is being referenced when there is a suspected phishing attack. Returns the most likely topic that has been
        targeted as a tuple. Some examples are below.
            ("brand", "Microsoft 365") -- lots of activity pointing towards Microsoft 365 resources
            ("brand", "Amazon")
            ("brand", "Fifth Third Bank")
            ("generic", "popular service") -- activity to things that often store popular service information, such as
                                                Clearbit, Gyazo, etc... (look for categorization here)
        Some challenges here will be determining whether the brand was loaded to be impersonated (and therefore
        identifying which site is impersonating it and correctly relabeling that site as the loaded site), or if it is
        actually the site being loaded and there's nothing interesting here. Also scenarios where the Malicious or
        Suspicious site wasn't in the interesting cluster.
    """
    logger.info("Searching for topics in interesting clusters...")
    topic = None
    root_domains_by_cluster = dict()
    root_domains_by_subcluster = dict()
    orgs_by_cluster = dict()
    orgs_by_subcluster = dict()
    suspected_phishing = []
    excluded_domains = ["sanejs.circl.lu"
        , "fonts.gstatic.com"
        , "fontawesome.com"
        , "www.google.com"
                        ]  # this is temporary until we have a chance to build a better solution
    excluded_orgs = [
        "Google Inc."
    ]
    if discovered_destination_purposes is not None:
        for d in discovered_destination_purposes:
            if d["site_purpose"] == "Phishing":
                suspected_phishing += [d["destination"]]
            else:
                excluded_domains += [d["destination"]]
    for cluster in interesting_clusters:
        logger.info("\tChecking cluster " + str(cluster) + " with the following destinations:")
        root_domains = dict()
        orgs = dict()
        for g in ordered_clusters[cluster]:
            dest_sans_port = g.destination_and_port[:g.destination_and_port.rfind(":")]
            logger.info("\t\t"
                         + g.destination_and_port
                         + " starting at "
                         + str(g.first_seen_in_this_group)
                         + " and ending at "
                         + str(g.last_seen_in_this_group)
                         )
            (root_domains, orgs, topic, skip) = collect_root_domains_and_orgs(g
                                                                              , excluded_domains
                                                                              , excluded_orgs
                                                                              , verdict["destinations"][dest_sans_port]
                                                                              , dest_sans_port
                                                                              , suspected_phishing
                                                                              , root_domains
                                                                              , orgs
                                                                              )
            if topic is not None:
                logger.info("Returning topic now from cluster analysis")
                return topic  # we short-circuited the logic
            if skip:
                continue  # nothing useful in this iteration, move on to the next one
        root_domains_by_cluster[cluster] = root_domains
        orgs_by_cluster[cluster] = orgs
    # print("Searching for topics in interesting subclusters...")
    for sub in interesting_subclusters:
        logger.info("\tChecking SUBcluster " + str(sub) + " with the following destinations:")
        root_domains = dict()
        orgs = dict()
        for g in activity_groups:
            if g.subcluster == sub:
                dest_sans_port = g.destination_and_port[:g.destination_and_port.rfind(":")]
                logger.info("\t\t"
                             + g.destination_and_port
                             + " starting at "
                             + str(g.first_seen_in_this_group)
                             + " and ending at "
                             + str(g.last_seen_in_this_group)
                             )
                (root_domains, orgs, topic, skip) = collect_root_domains_and_orgs(g
                                                                                  , excluded_domains
                                                                                  , excluded_orgs
                                                                                  , verdict["destinations"][
                                                                                      dest_sans_port]
                                                                                  , dest_sans_port
                                                                                  , suspected_phishing
                                                                                  , root_domains
                                                                                  , orgs
                                                                                  )
                if topic is not None:
                    logger.info("Returning topic now from SUBcluster analysis")
                    return topic  # we short-circuited the logic
                if skip:
                    continue  # nothing useful in this iteration, move on to the next one
        root_domains_by_subcluster[sub] = root_domains
        orgs_by_subcluster[sub] = orgs
    topic = get_most_likely_topic(root_domains_by_cluster
                                  , root_domains_by_subcluster
                                  , orgs_by_cluster
                                  , orgs_by_subcluster
                                  )
    return topic


def identify_uninteresting_pageloads(nonmalicious_pageloads, destinations_to_update):
    """This identifies all pageloads that have not been considered related to an attack (if there is an attack). This
        list will be used to push them to Common Activity, since they are expected to be uninteresting for the sample.
        This is useful because later we will be displaying just the name:port (first seen time) for each of these
        Destinations in a new "sites loaded" section of the details portion of the Summary call.
    """
    for destination_details in destinations_to_update:
        destination = destination_details["dest_and_port"]
        if destination in nonmalicious_pageloads.keys():
            logger.info("Removing " + destination + " from list of nonmalicious pageloads because it was found to be somehow related to an attack.")
            del nonmalicious_pageloads[destination]  # no longer something we want to move away from highlighting
    uninteresting_pageloads = nonmalicious_pageloads  # rename it now, since it's more correctly the things that aren't interesting
    return uninteresting_pageloads


def identify_uninteresting_attackvectors(dest_and_port_records, all_inferences, activity_groups, destinations_to_update):
    """This identifies all remaining Attack Vectors that are not pageloads and have not been considered related to an
        attack (if there is an attack). This list will be used to push them to Common Activity, since they are expected
        to be uninteresting for the sample.
    """
    uninteresting_attackvectors = dict()
    dests_to_keep = set()
    for destination_details in destinations_to_update:
        dests_to_keep.add(destination_details["dest_and_port"])
    for group in activity_groups:
        if group.category in ["Attack Vector"]:  # look for Attack Vectors that we haven't yet processed out
            inference_object = get_object(group.destination_and_port, all_inferences)
            if inference_object is not None:
                my_inferences = inference_object.associated_inferences
            else:
                my_inferences = dict()
            if "actual_page_loaded" not in my_inferences.keys() and group.destination_and_port not in dests_to_keep:
                logger.info("Adding " + group.destination_and_port + " to list of uninteresting Attack Vectors because it was NOT found to be somehow related to an attack.")
                uninteresting_attackvectors[group.destination_and_port] = (group, None, None)
    return uninteresting_attackvectors


def collect_nonmalicious_pageloads(verdict_records, all_inferences, activity_groups):
    """This collects info about the sites that -- after all other logic was completed -- are categorized as Attack
    Vector or Common Activity.
    """
    pageloads = dict()
    for group in activity_groups:
        if group.category in ["Common Activity", "Attack Vector"]:  # look for pageload inference in that destination
            inference_object = get_object(group.destination_and_port, all_inferences)
            if inference_object is not None:
                my_inferences = inference_object.associated_inferences
            else:
                my_inferences = dict()
            if "actual_page_loaded" in my_inferences.keys():
                try:
                    destination = utilities.dest_without_port(group.destination_and_port)
                    for d in verdict_records["destinations"][destination]["full_destinations"]:
                        if d["name_and_port"] == group.destination_and_port:
                            # check some shady things to avoid saving to nonmalicious pageloads
                            try:
                                if ("built_on_trusted" in my_inferences.keys()
                                    or "large_fileapp_download" in my_inferences.keys()
                                    or "fileapp_download" in my_inferences.keys()
                                    or not verdict_records["destinations"][destination]["has_IP"]
                                    or ("created_to_captured" in verdict_records["destinations"][destination]
                                        and verdict_records["destinations"][destination][
                                            "created_to_captured"].days <= 90
                                        )
                                ):
                                    logger.warning("Keeping unattributed pageload to "
                                                   + destination
                                                   + " in the list because it matched something that concerns us from burying it."
                                                   )
                                    continue
                            except:
                                logger.warning("Failed to successfully check for failsafes in nonmalicious pageloads")
                            earliest_group = d["activity_groups"][0]
                            try:
                                whois_org = verdict_records["destinations"][destination]["org_by_whois"]
                            except:
                                whois_org = None
                            try:
                                whois_root_domain = verdict_records["destinations"][destination]["root_domain_by_whois"]
                            except:
                                try:
                                    whois_root_domain = ".".join(destination.split(".")[-2:])
                                except:
                                    whois_root_domain = None
                            pageloads[group.destination_and_port] = (earliest_group, whois_org, whois_root_domain)
                            break # only need the earliest
                except:
                    logger.warning("Skipping destination because we couldn't find its groups...")
                    continue
    return pageloads


def find_topic_from_pageloads(nonmalicious_pageloads, all_inferences, activity_groups):
    """This logic looks at Attack Vectors or Common Activities that are identified as page loads and checks to see if
        there's any activity RIGHT before it that happens for the first time and is Suspicious or Malicious. If so, it
        labels this pageload as the likely topic.
    """
    topic = None
    possible_phish = None
    possible_phishes = []
    phishes_seen = []
    phishes_to_remove = []
    for group in activity_groups:
        if group.category in ["Suspicious Activity", "Malicious Activity"]:
            for pages in nonmalicious_pageloads.keys():
                try:
                    pageload_group = nonmalicious_pageloads[pages][0]
                    pageload_org = nonmalicious_pageloads[pages][1]
                    pageload_root_domain = nonmalicious_pageloads[pages][2]
                except:
                    logger.warning("Something failed while trying to get pageload info.")
                    continue
                #logger.info(group.category + " " + group.destination_and_port + " first seen at " + str(group.first_seen_in_this_group))
                #logger.info("Pageload " + pageload_group.destination_and_port + "first seen at " + str(pageload_group.first_seen_in_this_group))
                if utilities.get_destination_type(utilities.dest_without_port(group.destination_and_port)) == "IP":
                    continue  # we don't have enough knowledge here.
                if pageload_group.first_seen_in_this_group - 3 <= group.first_seen_in_this_group < pageload_group.first_seen_in_this_group:
                    # reasonably likely that this site was actually a site targeting this topic...
                    if (pageload_org is not None
                            and pageload_org not in org_hiding_registrars
                            and not re.search(org_hiding_registrars_regex, pageload_org)
                    ):
                        topic = ("brand", pageload_org)
                    elif pageload_root_domain is not None:
                        topic = ("generic", pageload_root_domain)
                    else:
                        topic = ("generic", utilities.dest_without_port(pageload_group.destination_and_port))
                    possible_phish = group.destination_and_port
                    logger.info("We think that "
                                + possible_phish
                                + " may actually be targeting "
                                + str(topic)
                                )
                    inference_object = get_object(possible_phish, all_inferences)
                    if possible_phish in phishes_seen:
                        logger.info("Actually...we saw " + possible_phish + " before, so we're going to remove it.")
                        # we're finding this multiple times as a possible phish, so it's probably NOT one...
                        if inference_object is not None:
                            inference_object.associated_inferences["is_phishing"] = False
                        phishes_to_remove += [possible_phish]
                    else:
                        phishes_seen += [possible_phish]
                        possible_phishes += [
                            {"destination": utilities.dest_without_port(possible_phish)
                                , "dest_and_port": possible_phish
                                , "category": "Malicious Activity"
                                , "confidence": "Medium"
                                , "site_purpose": "Phishing Portal"
                                , "cluster": group.associated_cluster
                                , "subcluster": group.subcluster
                                , "earliest_seen": group.first_seen_in_this_group
                             }
                        ]
                        if inference_object is not None:
                            inference_object.associated_inferences["is_phishing"] = False
    likeliest_phishes = []
    for p in possible_phishes:
        if p["dest_and_port"] not in phishes_to_remove:
            likeliest_phishes += [p]
        else:
            logger.info("Removing " + p["dest_and_port"] + " from final list of phishes.")
    return likeliest_phishes, topic


def discover_phishing(dest_and_port_records, ordered_clusters, interesting_clusters, topic, verdicts):
    """This Inference is an advanced one that first requires all of the preliminary knowledge about a sample to be
        completed. It uses Inferences plus interesting clusters of activity to determine follow-on details about which
        site (if any) is phishing. Returns any destinations found with the information that should be added.
    """
    if topic is None:
        logger.info("No topic information to use for identifying phishing.")
    else:
        if topic[0] == "brand":
            (root_domain, first_time, full_domain) = whois_analysis.get_root_domain_info(verdicts,
                                                                                         organization_name=topic[1]
                                                                                         )
        else:
            (root_domain, first_time, full_domain) = whois_analysis.get_root_domain_info(verdicts
                                                                                         , root_domain=topic[1]
                                                                                         )
            # TOOD: Need first time! Use first time to identify if it happened before the topic!
        if root_domain is None or first_time is None:
            topic = None
    destinations_to_update = []
    for cluster in interesting_clusters:
        logger.info("\tIn discover_phishing() call, cluster "
                     + str(cluster)
                     + " is interesting! Checking following destinations:"
                     )
        found_phishing = False
        for g in ordered_clusters[cluster]:
            if g.category in ["Malicious Activity", "Suspicious Activity"]:
                dest_sans_port = g.destination_and_port[:g.destination_and_port.rfind(":")]
                logger.info("\t\t"
                             + g.category
                             + " "
                             + g.destination_and_port
                             + " starting at "
                             + str(g.first_seen_in_this_group)
                             + " and ending at "
                             + str(g.last_seen_in_this_group)
                             )
                try:  # content with known metadata may not have evidence, so avoid exceptions here.
                    inference_object = dest_and_port_records[g.destination_and_port]["inferences"]
                    """
                    for dest_and_port_record in destination_data[dest_sans_port]["raw_evidence"]["full_destinations"]:
                        if dest_and_port_record["name_and_port"] == g.destination_and_port:
                            inference_object = dest_and_port_record["inferences"]
                            break
                    """
                except:
                    inference_object = None
                if g.has_known_metadata:
                    metadata = activity_grouping.get_highest_metadata_for_group(g)
                    if metadata is not None:
                        if "threatTags" in metadata.keys() and "Phishing" in metadata["threatTags"]:
                            if ("impactsTags" not in metadata.keys()
                                    or ("impactsTags" in metadata.keys()
                                        and not "CredentialsEntered" in metadata["impactsTags"]
                                    )
                            ):
                                destinations_to_update += [
                                    {"destination": dest_sans_port
                                        , "dest_and_port": g.destination_and_port
                                        , "category": "Malicious Activity"
                                        , "confidence": "High"
                                        , "site_purpose": metadata["description"]
                                        , "cluster": cluster
                                        , "subcluster": g.subcluster
                                        , "earliest_seen": g.first_seen_in_this_group
                                     }
                                ]
                                if inference_object is not None:
                                    inference_object.associated_inferences["is_phishing"] = True
                                    break
                if inference_object is None:  # content w/ known metadata may not have evidence, so avoid exceptions here.
                    continue
                if "has_autofill_form" in inference_object.associated_inferences:  # already confirms that it was the loaded page
                    destinations_to_update += [
                        {"destination": dest_sans_port
                            , "dest_and_port": g.destination_and_port
                            , "category": "Malicious Activity"
                            , "confidence": "High"
                            , "site_purpose": "Phishing"
                            , "cluster": cluster
                            , "subcluster": g.subcluster
                            , "earliest_seen": g.first_seen_in_this_group
                         }
                    ]
                    inference_object.associated_inferences["is_phishing"] = True
                    break
                elif not found_phishing and "actual_page_loaded" in inference_object.associated_inferences:
                    destinations_to_update += [
                        {"destination": dest_sans_port
                            , "dest_and_port": g.destination_and_port
                            , "category": "Malicious Activity"
                            , "confidence": "Medium-High"
                            , "site_purpose": "Phishing"
                            , "cluster": cluster
                            , "subcluster": g.subcluster
                            , "earliest_seen": g.first_seen_in_this_group
                         }
                    ]
                    inference_object.associated_inferences["is_phishing"] = True
                    break
                elif (not found_phishing
                      and topic is not None and
                      first_time is not None and (first_time - 3) < g.first_seen_in_this_group < first_time
                    ):  # happens within the 3 seconds right before the page load
                        destinations_to_update += [
                            {"destination": dest_sans_port
                                , "dest_and_port": g.destination_and_port
                                , "category": "Malicious Activity"
                                , "confidence": "Medium"
                                , "site_purpose": "Phishing"
                                , "cluster": cluster
                                , "subcluster": g.subcluster
                                , "earliest_seen": g.first_seen_in_this_group
                             }
                        ]
                        inference_object.associated_inferences["is_phishing"] = True
                        break
    return destinations_to_update


def discover_impact(destination_data, ordered_clusters, interesting_clusters):
    """This Inference is an advanced one that first requires all of the preliminary knowledge about a sample to be
        completed. It uses Inferences plus interesting clusters of activity to determine follow-on details about which
        site (if any) is an impact. Returns any destinations found with the information that should be added.
    """
    destinations_to_update = []
    found_phishing = False
    phishing_site_data = []
    for cluster in interesting_clusters:
        logger.info("\tIn discover_impact() call, cluster "
                     + str(cluster)
                     + " is interesting! Checking following destinations:"
                     )
        for g in ordered_clusters[cluster]:
            if g.category in ["Malicious Activity", "Impact", "Common Activity"]:
                logger.info("\t\t"
                             + g.category
                             + " "
                             + g.destination_and_port
                             + " starting at "
                             + str(g.first_seen_in_this_group)
                             + " and ending at "
                             + str(g.last_seen_in_this_group)
                             )
                # Common Activity refers to things like the way legitimate login portals collect credentials. They may be the way we see activity happening.
                dest_sans_port = g.destination_and_port[:g.destination_and_port.rfind(":")]
                inference_object = None
                try:
                    raw_evidence = destination_data[dest_sans_port]["raw_evidence"]
                except:
                    raw_evidence = dict()  # just make it empty
                try:
                    for dest_and_port_record in raw_evidence["full_destinations"]:
                        if dest_and_port_record["name_and_port"] == g.destination_and_port:
                            inference_object = dest_and_port_record["inferences"]
                            break
                except:
                    inference_object = None
                if g.has_known_metadata:
                    metadata = activity_grouping.get_highest_metadata_for_group(g)
                    if metadata is not None:
                        if "impactsTags" in metadata.keys() and "CredentialsEntered" in metadata["impactsTags"]:
                            destinations_to_update += [
                                {"destination": dest_sans_port
                                    , "dest_and_port": g.destination_and_port
                                    , "category": "Impact"
                                    , "confidence": "High"
                                    , "site_purpose": metadata["description"]
                                    , "cluster": cluster
                                    , "subcluster": g.subcluster
                                    , "earliest_seen": g.first_seen_in_this_group
                                 }
                            ]
                            try:
                                inference_object.associated_inferences[
                                    "information_collection"] = True  # because phishing doesn't only collect creds...it could collect CC info, etc...
                            except:
                                logger.info(
                                    "Somehow we didn't have an Inference object for something that should have had one...")
                            break
                if inference_object is not None and "is_phishing" in inference_object.associated_inferences:
                    found_phishing = True  # we can only find impacts (such as C2) AFTER phishing activity
                    phishing_site_data = [inference_object, g]
                    continue
                if found_phishing and g.category in ["Malicious Activity",
                                                     "Impact"] and "common_c2_categories" in raw_evidence:
                    destinations_to_update += [
                        {"destination": dest_sans_port
                            , "dest_and_port": g.destination_and_port
                            , "category": "Impact"
                            , "confidence": "Medium-High"
                            , "site_purpose": "Credential Collection"
                            , "cluster": cluster
                            , "subcluster": g.subcluster
                            , "earliest_seen": g.first_seen_in_this_group
                         }
                    ]
                    try:
                        inference_object.associated_inferences[
                            "information_collection"] = True  # because phishing doesn't only collect creds...it could collect CC info, etc...
                    except:
                        logger.info(
                            "Somehow we didn't have an Inference object for something that should have had one...")
                    break
                # TODO: more decisions based on clusters to either elevate Impacts, lower Suspicious activity, or identify if there's actually anything to care about/respond to
    if len(destinations_to_update) == 0 and len(phishing_site_data) > 0:
        # we need to check and see if there's a chance that this site itself is ALSO the Impact, or if it's possible.
        try:
            inference_object = phishing_site_data[0]
            g = phishing_site_data[1]
            logger.info("Checking to see if it's possible that " + g.destination_and_port + " is also the impact site.")
            """
            num_acts = len(inference_object.activities_list)
            if num_acts >= 2:
                if num_acts >= 5:
                    confidence = "High"
                elif 3 <= num_acts < 5:
                    confidence = "Medium-High"
                else:
                    confidence = "Medium"
            elif (len(inference_object.activities_list) == 1
                  and inference_object.last_seen_in_this_sample - inference_object.first_seen_in_this_sample >= 10
            ):
                confidence = "Low"
            """
            if "has_autofill_form" in inference_object.associated_inferences:  # likeliest scenario that it's also creds site
                destinations_to_update += [
                    {"destination": utilities.dest_without_port(g.destination_and_port)
                        , "dest_and_port": g.destination_and_port
                        , "category": "Impact"
                        , "confidence": "Medium-High"
                        , "site_purpose": "Credential Collection"
                        , "cluster": g.associated_cluster
                        , "subcluster": g.subcluster
                        , "earliest_seen": g.first_seen_in_this_group
                     }
                ]
            try:
                inference_object.associated_inferences[
                    "information_collection"] = True  # because phishing doesn't only collect creds...it could collect CC info, etc...
            except:
                logger.info(
                    "Somehow we didn't have an Inference object for something that should have had one...")
        except:
            logger.info("Something went wrong while trying to check if phishing site was also impact site.")

    return destinations_to_update


def discover_attack_vector(destination_data, ordered_clusters, interesting_clusters):
    """This Inference is an advanced one that first requires all of the preliminary knowledge about a sample to be
        completed. It uses Inferences plus interesting clusters of activity to determine follow-on details about which
        site (if any) is an Attack Vector. Returns any destinations found with the information that should be added.
    """
    destinations_to_update = []
    logging.info("In discover_attack_vector call.")
    for cluster in interesting_clusters:
        for g in ordered_clusters[cluster]:
            dest_sans_port = g.destination_and_port[:g.destination_and_port.rfind(":")]
            inference_object = None
            try:
                raw_evidence = destination_data[dest_sans_port]["raw_evidence"]
            except:
                raw_evidence = dict()
            try:
                for dest_and_port_record in raw_evidence["full_destinations"]:
                    if dest_and_port_record["name_and_port"] == g.destination_and_port:
                        inference_object = dest_and_port_record["inferences"]
                        break
            except:
                inference_object = None
            if g.category in ["Attack Vector", "Common Activity"]:
                if g.has_known_metadata:
                    metadata = activity_grouping.get_highest_metadata_for_group(g)
                    if metadata is not None:
                        logging.info("Metadata: " + str(metadata.items()))
                else:
                    logging.info(g.destination_and_port + "(" + g.category + ") evidence:")
                    logging.info(str(raw_evidence))
                    if inference_object is not None:
                        logging.info("Inferences: " + str(inference_object.associated_inferences))
                # we're looking for things that may be the actual attack vector for this sample
            if g.category == "Malicious Activity":
                if dest_sans_port not in destination_data:
                    continue
                if inference_object is not None and "is_phishing" in inference_object.associated_inferences:
                    break  # if we hit the phishing group, we already passed any potential Attack Vectors
                # TODO: more decisions based on clusters to either elevate Impacts, lower Suspicious activity, or identify if there's actually anything to care about/respond to
    return destinations_to_update


def guilty_by_association(guilty_destinations, activity_groups):
    """For destinations that have information that must be updated (because they are Phishing, Impact, etc...), label
        other subdomains of that same site (UNLESS it's known built on trusted or a known site that wasn't already
        identified as known malicious) with Malicious Activity.
    """
    excluded_sites = ["google.com", "googleapis.com"]  # TODO: in future, exclude highly common sites programmatically!
    associated_destinations = []
    for destination_details in guilty_destinations:
        destination_name = destination_details["destination"]
        if destination_details["category"] not in "Attack Vector":
            if destination_name.count(".") >= 2:
                dest_without_port = destination_name.split(":")[0]
                portless_dest_minus_top = ".".join(dest_without_port.split(".")[1:])
                for group in activity_groups:
                    if (
                            portless_dest_minus_top in group.destination_and_port
                            and group.destination_and_port != destination_name
                            and not group.has_known_metadata
                            and portless_dest_minus_top not in excluded_sites
                    ):
                        # faster way to check if we have a substring with a bit of possible error...
                        associated_destinations += [{"destination": group.destination_and_port.split(":")[0]
                                                        , "dest_and_port": group.destination_and_port
                                                        , "category": destination_details["category"]
                                                        , "confidence": destination_details["confidence"]
                                                        , "site_purpose": destination_details["site_purpose"]
                                                        , "cluster": group.associated_cluster
                                                        , "subcluster": group.subcluster
                                                        , "earliest_seen": group.first_seen_in_this_group
                                                     }]
    return (guilty_destinations + associated_destinations)


def guilty_by_cluster(guilty_destinations, activity_groups):
    """For destinations that have information that must be updated (because they are Phishing, Impact, etc...), label
        other sites that were listed as suspicious in that cluster or subcluster as malicious. Also attempt to find any
        more believable attack vectors.
    """
    logger.info("In guilty_by_cluster() call")
    clusters_to_update = set()
    subclusters_to_update = set()
    clustered_update_destinations = []
    all_bad_destinations = set()
    for destination_details in guilty_destinations:
        destination_name = destination_details["destination"]
        if destination_details["category"] not in "Attack Vector":
            clusters_to_update.add(destination_details["cluster"])
            subclusters_to_update.add(destination_details["subcluster"])
            all_bad_destinations.add(destination_name)
    if len(all_bad_destinations) == 0:
        sus_sites = set()
        had_domain = False
        for g in activity_groups:
            if g.category == "Suspicious Activity":
                sus_sites.add(g.destination_and_port.split(":")[0])
                if utilities.get_destination_type(utilities.dest_without_port(g.destination_and_port)) == "domain":
                    had_domain = True
        if len(sus_sites) == 1:
            confidence = "Low"
        elif 1 < len(sus_sites) < 5:
            confidence = "Medium"
        elif len(sus_sites) >= 5:
            confidence = "Medium-High"
        else:
            confidence = "Low"
        for g in activity_groups:
            if g.category == "Suspicious Activity":
                inferred_category = g.category
                inferred_site_purpose = "Potentially Suspicious activity"
            elif g.category == "Attack Vector":
                if had_domain:  # was a domain name (which we're better at identifying) listed as a Suspicious site
                    inferred_site_purpose = "Attack Vector"
                    inferred_category = "Attack Vector"
                else:
                    continue
            else:
                continue
                # logger.info("Got an unexpected category " + str(g.category))
                # inferred_site_purpose = "Unknown"
                # inferred_category = g.category
            clustered_update_destinations += [{"destination": g.destination_and_port.split(":")[0]
                                                  , "dest_and_port": g.destination_and_port
                                                  , "category": inferred_category
                                                  , "confidence": confidence
                                                  , "site_purpose": inferred_site_purpose
                                                  , "earliest_seen": g.first_seen_in_this_group
                                               }]
    else:
        for g in activity_groups:
            if ((
                    (g.associated_cluster in clusters_to_update)
                    or (g.subcluster in subclusters_to_update)
            ) and g.destination_and_port not in all_bad_destinations
            ):
                if (g.category in ["Suspicious Activity"]
                        and utilities.get_destination_type(
                            utilities.dest_without_port(g.destination_and_port)) == "domain"
                        and not g.has_known_metadata
                ):
                    inferred_site_purpose = "Related to Attack"
                    inferred_category = "Malicious Activity"
                elif g.category in ["Attack Vector"]:
                    inferred_site_purpose = "Attack Vector"
                    inferred_category = "Attack Vector"
                else:
                    continue
                clustered_update_destinations += [{"destination": g.destination_and_port.split(":")[0]
                                                      , "dest_and_port": g.destination_and_port
                                                      , "category": inferred_category
                                                      , "confidence": "Medium"
                                                      , "site_purpose": inferred_site_purpose
                                                      , "earliest_seen": g.first_seen_in_this_group
                                                   }]
    return (guilty_destinations + clustered_update_destinations)


def is_associated_with_authentication(inference_object, bucketed_activities, activity_groups):
    """Not currently implemented, but desired!
        Suspicious sites that have majorDownloadViaLongSession or someDataViaLongSession flows closest to
        Destinations/Behaviors/Events tagged with securityTags containing "Authentication" or "SuccessfulAuthentication"
        that would generally come after a site (such as a login assets loading) are the reason for that behavior. This
        enhances our ability to understand which sites may be most interesting to examine.
    """

    interesting_flow_categories = ["someDataDownloadedViaLongSession"
        , "majorDataDownloadedViaLongSession"
                                   ]
    relevant_tags = ["Authentication", "SuccessfulAuthentication"]


def is_caused_by_or_causing_seen_near_bad(inference_object, all_bucketed_activities, activity_groups):
    """Not currently implemented, but desired!
        Suspicious sites (labeled with category "Suspicious Behavior" in activity_groups) that have download flows (with
        the exception of briefDownload) closest to “seen nearby bad” Destinations/Behaviors/Events that would generally
        come after a site (such as a UI component loading) are the source of that behavior. This would help us to
        understand how many seen nearby bad behaviors are associated with a suspicious site, which would help us to
        modify the score appropriately.
    """

    nonbrief_download_flows = ["someResourcesDownloaded"
        , "majorResourcesDownloaded"
        , "someContentDownloaded"
        , "majorContentDownloaded"
        , "someDataDownloadedViaLongSession"
        , "majorDataDownloadedViaLongSession"
                               ]
    candidate = None
    for group in activity_groups:
        if group.destination_and_port == inference_object.destination_and_port:
            for bucket in inference_object.my_buckets:
                if bucket["flowCategory"] in nonbrief_download_flows:
                    candidate = bucket
                    break
            if candidate is not None:
                start = candidate["minRelativeStart"]
