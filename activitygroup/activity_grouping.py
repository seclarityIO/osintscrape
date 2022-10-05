"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import ast
import logging

from activitygroup import activity_group

logger = logging.getLogger("ActivityGrouping")

"""This module collects all activity (which is a superset of Secflows, Destinations, Behaviors, and Events) for a sample
    into groups. These groups are what make up Figure #4 in our NetworkSage introduction blog post:
    https://www.seclarity.io/resources/blog/introducing-networksage/
    Specific details for the meat of the logic in this module is found within the comments for those functions.
"""


def create_activity_groups(labeled_activities):
    """This function takes all activities from a sample (each of which contains an "interesting" label of True or False,
        and all of which are sorted ascending by relativeStart) and groups them by destinationData field into groups
        where their timing intersects. Each of those activity groups is then labeled with a category from the following
        (in this order):
        1. Malicious Activities
        2. Attack Vectors
        3. Impact
        4. Common Activities
        5. Suspicious Activities

        NOTE that each step in the above collection immediately removes the associated activity from the list of
        activities to process. No single activity should ever be considered for a second categorization once already
        categorized (it can later be relabeled, but it cannot have two different categories at once).
    """
    activity_groups = []

    for activity in labeled_activities:
        # we want to group everything here.
        dest = activity["secflow"]["destinationData"]
        start = float(activity["secflow"]["relativeStart"])
        end = start + float(activity["secflow"]["duration"])
        ag = get_existing_activity_group(dest, start, end, activity_groups)
        if ag is None:
            ag = activity_group.ActivityGroup(dest, start, end)
            activity_groups += [ag]
        if add_to_malicious_activity(activity, ag, activity_groups):
            continue  # processed it, so move to next activity
        if add_to_attack_vectors(activity, ag, activity_groups):
            continue
        if add_to_impact(activity, ag, activity_groups):
            continue
        if add_to_common_activity(activity, ag, activity_groups):
            continue
        if add_to_suspicious_activity(activity, ag, activity_groups):
            continue
        logger.error("(SHOULDN'T HAPPEN!!!!) Somehow we still have activity left for "
                     + dest
                     )
    return activity_groups


def add_to_malicious_activity(activity, ag, activity_groups):
    """An activity is added to the Malicious Activity category when:
        + an Event, Behavior, or Destination has a relevance of "knownBad" and none of their tags indicate that they're
            an Impact.
        + an unenriched secflow has the same destinationData field as one of the above.
    """
    # print("Trying to associate", activity["secflow"]["destinationData"], "with Malicious Activity")
    saved = False
    if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
        if type(activity["event"]) == str:
            try:
                event_dict = ast.literal_eval(activity["event"])
                activity["event"] = event_dict
            except:
                logger.info("Something is weird with event dictionary.")
                pass
        # print("Mal activity case, data:", activity)
        if (
                ("relevance" in activity["event"].keys()
                 and activity["event"]["relevance"] == "knownBad"
                )
                and ("impactsTags" not in activity["event"].keys()
                     or len(activity["event"]["impactsTags"]) == 0
        )
        ):
            """capture this Event, remove from list of stuff to look at (which may not be necessary, since we're 
            iterating through a list in order), and update the Activity Group
            """
            ag.overlapping_activities += [activity]
            ag.category = "Malicious Activity"
            saved = True
    elif activity["behavior"] != {}:
        if (
                ("relevance" in activity["behavior"].keys()
                 and activity["behavior"]["relevance"] == "knownBad"
                )
                and ("impactsTags" not in activity["behavior"].keys()
                     or len(activity["behavior"]["impactsTags"]) == 0
        )
        ):
            """capture this Behavior, remove from list of stuff to look at (which may not be necessary, since we're 
            iterating through a list in order), and update the Activity Group
            """
            ag.overlapping_activities += [activity]
            ag.category = "Malicious Activity"
            saved = True
    elif activity["destination"] != {}:
        if (
                ("relevance" in activity["destination"].keys()
                 and activity["destination"]["relevance"] == "knownBad"
                )
                and ("impactsTags" not in activity["destination"].keys()
                     or len(activity["destination"]["impactsTags"]) == 0
        )
        ):
            """capture this Destination, remove from list of stuff to look at (which may not be necessary, since we're 
            iterating through a list in order), and update the Activity Group
            """
            ag.overlapping_activities += [activity]
            ag.category = "Malicious Activity"
            saved = True
    else:  # un-enriched secflow
        if ag.category == "Malicious Activity":  # is not None:
            ag.overlapping_activities += [activity]
            saved = True
        else:
            """the initial activity group we were looking at didn't match (likely the first item for a destination), so 
                now we need to check all activity groups with our name to see if any match us and have this category.
            """
            for group in activity_groups:
                if group.destination_and_port == ag.destination_and_port and group.category == "Malicious Activity":
                    ag.category = "Malicious Activity"
                    ag.overlapping_activities += [activity]
                    saved = True
                    break
    if saved:
        ag.has_known_metadata = True
        ag.update_last_seen(activity)
    return saved


def add_to_attack_vectors(activity, ag, activity_groups):
    """An activity is added to the Attack Vector category when:
        + an Event, Behavior, or Destination has a tag stating that it is an Attack Vector.
        + an unenriched secflow has the same destinationData field as one of the above.
    """
    saved = False
    if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
        if "attackVectorTags" in activity["event"].keys() and len(activity["event"]["attackVectorTags"]) > 0:
            ag.overlapping_activities += [activity]
            ag.category = "Attack Vector"
            saved = True
    elif activity["behavior"] != {}:
        if "attackVectorTags" in activity["behavior"].keys() and len(activity["behavior"]["attackVectorTags"]) > 0:
            ag.overlapping_activities += [activity]
            ag.category = "Attack Vector"
            saved = True
    elif activity["destination"] != {}:
        if "attackVectorTags" in activity["destination"].keys() and len(
                activity["destination"]["attackVectorTags"]) > 0:
            ag.overlapping_activities += [activity]
            ag.category = "Attack Vector"
            saved = True
    else:  # un-enriched secflow
        if ag.category == "Attack Vector":
            ag.overlapping_activities += [activity]
            saved = True
        else:
            """the initial activity group we were looking at didn't match (likely the first item for a destination), so 
                now we need to check all activity groups with our name to see if any match us and have this category
            """
            for group in activity_groups:
                if group.destination_and_port == ag.destination_and_port and group.category == "Attack Vector":
                    ag.category = "Attack Vector"
                    ag.overlapping_activities += [activity]
                    saved = True
                    break
    if saved:
        ag.has_known_metadata = True
        ag.update_last_seen(activity)
    return saved


def add_to_impact(activity, ag, activity_groups):
    """An activity is added to the Impact category when:
        + when an Event, Behavior, or Destination has a tag stating that it is an Impact.
        + when an unenriched secflow has the same destinationData field as one of the above.
    """
    saved = False
    if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
        if "impactsTags" in activity["event"].keys() and len(activity["event"]["impactsTags"]) > 0:
            ag.overlapping_activities += [activity]
            ag.category = "Impact"
            saved = True
    elif activity["behavior"] != {}:
        if "impactsTags" in activity["behavior"].keys() and len(activity["behavior"]["impactsTags"]) > 0:
            ag.overlapping_activities += [activity]
            ag.category = "Impact"
            saved = True
    elif activity["destination"] != {}:
        if "impactsTags" in activity["destination"].keys() and len(activity["destination"]["impactsTags"]) > 0:
            ag.overlapping_activities += [activity]
            ag.category = "Impact"
            saved = True
    else:  # un-enriched secflow
        if ag.category == "Impact":
            ag.overlapping_activities += [activity]
            saved = True
        else:
            """the initial activity group we were looking at didn't match (likely the first item for a destination), 
                so now we need to check all activity groups with our name to see if any match us and have this category
            """
            for group in activity_groups:
                if group.destination_and_port == ag.destination_and_port and group.category == "Impact":
                    ag.category = "Impact"
                    ag.overlapping_activities += [activity]
                    saved = True
                    break
    if saved:
        ag.has_known_metadata = True
        ag.update_last_seen(activity)
    return saved


def add_to_common_activity(activity, ag, activity_groups):
    """An activity is added to the Common Activity category when:
        + an Event or Behavior does NOT contain a tag indicating that it's an Impact or Attack Vector, does NOT have a
            relevance of "knownBad", and does NOT have an "AI Discovered Bad" attribute of "yes" (this last piece
            doesn't currently exist, and may never exist).
        + a Destination does NOT have a relevance of "knownBad", and has been seen for more than 168 hours (this period
            gives us time to identify interesting activity and label it; latter portion currently not implemented!).
        + a Destination does NOT have a relevance of "knownBad", and has been seen in at least 5 samples.
        + a Destination has a relevance of "seenNearBad".
        + an unenriched secflow has the same destinationData field as one of the above.
    """
    saved = False
    if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
        if (
                ("impactsTags" not in activity["event"].keys()
                 or len(activity["event"]["impactsTags"]) == 0
                )
                and ("attackVectorTags" not in activity["event"].keys()
                     or len(activity["event"]["attackVectorTags"]) == 0
        )
                and ("relevance" not in activity["event"].keys()
                     or ("relevance" not in activity["event"].keys()
                         or activity["event"]["relevance"] != "knownBad"
                     )
        )
        ):
            if "aiDiscoveredBad" in activity["event"].keys() and activity["event"][
                "aiDiscoveredBad"] == True:  # TODO: Doesn't currently exist....future work needed!
                saved = False
            else:
                ag.overlapping_activities += [activity]
                ag.category = "Common Activity"
                ag.has_known_metadata = True
                saved = True
    elif activity["behavior"] != {}:
        if (
                ("impactsTags" not in activity["behavior"].keys()
                 or len(activity["behavior"]["impactsTags"]) == 0
                )
                and ("attackVectorTags" not in activity["behavior"].keys()
                     or len(activity["behavior"]["attackVectorTags"]) == 0
        )
                and ("relevance" not in activity["behavior"].keys()
                     or activity["behavior"]["relevance"] != "knownBad"
        )
        ):
            ag.overlapping_activities += [activity]
            ag.category = "Common Activity"
            ag.has_known_metadata = True
            saved = True
    elif activity["destination"] != {}:
        if (
                ("impactsTags" not in activity["destination"].keys()
                 or len(activity["destination"]["impactsTags"]) == 0
                )
                and ("attackVectorTags" not in activity["destination"].keys()
                     or len(activity["destination"]["attackVectorTags"]) == 0
        )
                and ("relevance" not in activity["destination"].keys()
                     or activity["destination"]["relevance"] != "knownBad"
        )
        ):
            ag.overlapping_activities += [activity]
            ag.category = "Common Activity"
            ag.has_known_metadata = True
            saved = True
        elif (
                ("relevance" not in activity["destination"].keys()
                 or activity["destination"]["relevance"] != "knownBad"
                )
                and activity["secflow"]["flowCategory"] == "keepAlive"
        ):  # NOTE: this second clause is just a dummy do-nothing placeholder until we have something like the following: activity["destination"]["first_seen_ever"] > (now-5d):
            ag.overlapping_activities += [activity]
            ag.category = "Common Activity"
            ag.has_known_metadata = True
            saved = True
        elif (
                ("relevance" not in activity["destination"].keys()
                 or activity["destination"]["relevance"] != "knownBad"
                )
                and activity["secflow"]["flowIdCount"] >= 5
        ):
            ag.overlapping_activities += [activity]
            ag.category = "Common Activity"
            ag.has_known_metadata = True
            saved = True
    else:  # un-enriched secflow
        if ag.category == "Common Activity":  # is not None:
            ag.overlapping_activities += [activity]
            saved = True
        else:
            """the initial activity group we were looking at didn't match (likely the first item for a destination), so 
                now we need to check all activity groups with our name to see if any match us and have this category
            """
            for group in activity_groups:
                if group.destination_and_port == ag.destination_and_port and group.category == "Common Activity":
                    ag.category = "Common Activity"
                    ag.overlapping_activities += [activity]
                    saved = True
                    break
    if saved:
        ag.update_last_seen(activity)
    return saved


def add_to_suspicious_activity(activity, ag, activity_groups):
    """An activity is added to the Suspicious Activity category when:
        + when an Event, Behavior, or Destination contains an "AI Discovered Bad" attribute of "yes".
        + whatever remains in the labeled activities where the "interesting" attribute is True.
    """
    saved = False
    if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
        if "aiDiscoveredBad" in activity["event"].keys() and activity["event"][
            "aiDiscoveredBad"] == True:  # Doesn't currently exist, FWIW....maybe use analyzeSearch results here for now.
            ag.overlapping_activities += [activity]
            ag.category = "Suspicious Activity"
            ag.has_known_metadata = True
            saved = True
    elif activity["behavior"] != {}:
        if "aiDiscoveredBad" in activity["behavior"].keys() and activity["behavior"][
            "aiDiscoveredBad"] == True:  # Doesn't currently exist, FWIW....maybe use analyzeSearch results here for now.
            ag.overlapping_activities += [activity]
            ag.category = "Suspicious Activity"
            ag.has_known_metadata = True
            saved = True
    elif activity["destination"] != {}:
        if "aiDiscoveredBad" in activity["destination"].keys() and activity["destination"][
            "aiDiscoveredBad"] == True:  # Doesn't currently exist, FWIW....maybe use analyzeSearch results here for now.
            ag.overlapping_activities += [activity]
            ag.category = "Suspicious Activity"
            ag.has_known_metadata = True
            saved = True
    else:  # un-enriched secflow
        if activity["secflow"]["destinationData"] == ag.destination_and_port and ag.category == "Suspicious Activity":
            ag.overlapping_activities += [activity]
            ag.category = "Suspicious Activity"
            saved = True
        else:  # the initial activity group we were looking at didn't match (likely the first item for a destination), so now we need to check all activity groups with our name to see if any match us and have this category
            for group in activity_groups:
                if group.destination_and_port == ag.destination_and_port and group.category == "Suspicious Activity":
                    ag.category = "Suspicious Activity"
                    ag.overlapping_activities += [activity]
                    saved = True
                    break
    if not saved:  # Suspicious activity is the last thing, so we need to save it here.
        saved = True
        ag.category = "Suspicious Activity"
        ag.overlapping_activities += [activity]
    if saved:
        ag.update_last_seen(activity)
    return saved


def get_title_for_activity_group(activity_group):
    """Returns the most useful title for this activity group.
    """
    title = ""
    for activity in activity_group.overlapping_activities:
        if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
            if title == "":
                title = activity["event"]["title"]
            else:
                return title  # grab the first one
        elif "behavior" in activity.keys() and activity["behavior"] != {}:
            if title == "":
                title = activity["behavior"]["title"]
        elif "destination" in activity.keys() and activity["destination"] != {}:
            if title == "":
                title = activity["destination"]["title"]
        else:
            if title == "":
                title = activity["secflow"]["destinationData"]
    return title


def get_description_for_activity_group(activity_group):
    """Returns the most useful description for this activity group.
    """
    desc = ""
    if activity_group.description is not None:
        return activity_group.description
    for activity in activity_group.overlapping_activities:
        if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
            if desc == "":
                desc = activity["event"]["description"]
            else:
                return desc  # grab the first one
        elif "behavior" in activity.keys() and activity["behavior"] != {}:
            if desc == "":
                desc = activity["behavior"]["description"]
        elif "destination" in activity.keys() and activity["destination"] != {}:
            if desc == "":
                desc = activity["destination"]["description"]
        activity_group.description = desc
    return activity_group.description


def get_activity_groups_for_destination(dest, activity_groups):
    """Returns a list of all activity groups in the order in which they were found in the sample.
    """
    groups = []
    # print("Looking for activity groups for", dest)
    for group in activity_groups:
        # print("Group's destination name is", group.destination_and_port)
        if dest == group.destination_and_port:
            # print("Collecting group with category", group.category)
            groups += [group]
    return groups


def get_associated_clusters_for_destination(dest, activity_groups):
    """Returns the list of associated clusters (ints) for this destination.
    """
    clusters = []
    for group in activity_groups:
        if dest == group.destination_and_port:
            clusters += [group.associated_cluster]
    return clusters


def relabel_category_for_destination(dest_activity_groups, new_category, confidence):
    """Sometimes -- as we collect more information -- we learn that there's actually a better label for some existing
        Destination and its activity groups. This helper function relabels the category we've assigned to a destination
        across all of its activity groups.
    """
    for group in dest_activity_groups:
        group.category = new_category
        group.confidence = confidence


def update_confidence_for_destination(dest_activity_groups, confidence):
    """Sometimes -- as we collect more information -- we become more or less confident of the category already
        associated with a destination. This helper function updates the confidence we've assigned to a destination
        across all of its activity groups.
    """
    for group in dest_activity_groups:
        group.confidence = confidence


def save_description_for_destination(dest_activity_groups, description):
    """If we don't have any description for a destination (such as those that aren't known to the security community),
        this updates the description assigned to a destination across all of its activity groups.
    """
    for group in dest_activity_groups:
        if group.description is None or group.description == "":
            group.description = description
        # don't overwrite existing descriptions


def get_existing_activity_group(dest, start, end, activity_groups):
    """Whenever a destination already has been grouped, we should group a new activity with it IF its timing (start or
        end) overlaps with the existing group.
    """
    for group in activity_groups:
        if dest == group.destination_and_port and group.first_seen_in_this_group <= start < group.last_seen_in_this_group:
            return group  # found it in list, so work with it
    return None


def get_highest_metadata_for_group(group):
    """It is useful to be able to get the highest level of metadata that we have about some Activity Group so that we
        can make useful decisions on that data in other places (for example, on tags that exist). This function makes
        that process easy.
    """
    metadata = None
    if group.has_known_metadata:
        for act in group.overlapping_activities:
            try:
                meta = "event"
                if act[meta]["title"] != "":
                    # title MUST exist if there is actual metadata. If it doesn't exist we hit exception.
                    return act[meta]
            except:
                try:
                    meta = "behavior"
                    if act[meta]["title"] != "":
                        # title MUST exist if there is actual metadata. If it doesn't exist we hit exception.
                        return act[meta]
                except:
                    try:
                        meta = "destination"
                        if act[meta]["title"] != "":
                            # title MUST exist if there is actual metadata. If it doesn't exist we hit exception.
                            return act[meta]
                    except:
                        logger.info("Didn't find metadata for activity group.")
    return metadata
