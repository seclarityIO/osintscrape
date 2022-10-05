"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import logging

logger = logging.getLogger("Events")

"""This module implements Events in Python to enable us to correctly keep all samples up to date with greater details.
"""


def identify_events(all_activities):
    """Takes all activities (that already have information about existing Destinations, Behaviors, and Events from the
        existing NetworkSage logic) and tries to identify Events that have not yet been populated in the backend data.
        Stores these exactly as they are in the Events metadata today.
    """
    logger.info("Supplementary Events capability (not implemented).")
    acts_with_behaviors = []
    if all_activities:
        for activity in all_activities:
            # first, collect those that have Behavior metadata
            if activity["behavior"] != {}:
                acts_with_behaviors += [activity["secflow"]]
    return all_activities
