"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import json

"""The ActivityGroup class is used to collect groups of activities to the same destination that are active at the same
    time (i.e. their start and end times overlap to some level). We use this to collect groups that are used for
    Inferences and for understanding which groups of activity may be related (by their associated cluster)
"""


class ActivityGroup():
    def __init__(self, dest, start, end):
        self.destination_and_port = dest
        self.first_seen_in_this_group = start
        self.last_seen_in_this_group = end
        self.associated_cluster = -1  # an identifier for a cluster of groups (to identify groups that may be related)
        self.subcluster = -1  # an identifier for groups within an associated cluster that may be related by start time
        self.has_known_metadata = False  # metadata from NetworkSage (Destinations/Behaviors/Events)
        self.category = None  # One of Attack Vector, Common Activity, Suspicious Activity, Malicious Activity, or Impact
        self.description = None  # what we know about the group based on our full analysis
        self.confidence = ""  # our confidence in the category given to this group
        self.overlapping_activities = []  # a list to collect all activities for a particular destination name that overlap in time

    def update_last_seen(self, activity):
        self.last_seen_in_this_group = max(self.last_seen_in_this_group
                                           , float(activity["secflow"]["relativeStart"])
                                           + float(activity["secflow"]["duration"])
                                           )

    def to_json(self, skip=["category"]):
        """Create a JSON-serialized version of an ActivityGroup object. Currently not used.
        """
        for key in skip:
            try:
                self.__dict__.pop(key)  # remove some keys that we don't need for user output
            except:
                continue
        return json.dumps(self
                          , default=lambda o: o.__dict__
                          )

    def prep_group_output(self, skip=["category"]):
        """Prepares an ActivityGroup object for being saved to a file by removing fields that we don't want to expose.
        """
        for key in skip:
            try:
                self.__dict__.pop(key)  # remove some keys that we don't need for user output
            except:
                continue
        return self.__dict__

    def __getstate__(self):  # for proper pickling
        return self.__dict__

    def __setstate__(self, d):  # for proper unpickling
        self.__dict__ = d

    def __str__(self):
        return (str(self.__class__)
                + ":"
                + str(self.__dict__)
                )
