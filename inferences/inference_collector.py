"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import logging
logger = logging.getLogger("InferenceCollector")


class InferenceCollector():
    def __init__(self, dest, activities, buckets, category):
        self.destination_and_port = dest
        self.activities_list = activities
        self.category = category
        self.my_buckets = buckets
        if self.activities_list is not None and self.activities_list != []:
            self.first_seen_in_this_sample = float(self.activities_list[0]["secflow"]["relativeStart"])
            self.last_seen_in_this_sample = float(self.activities_list[-1]["secflow"]["relativeStart"]) + float(
                self.activities_list[-1]["secflow"]["duration"])
        else:
            self.first_seen_in_this_sample = None
            self.last_seen_in_this_sample = None
        self.associated_inferences = dict()  # dict contains inference name as key, tuple of (description to print later, score modulation) as value

    def set_first_last_times(self):
        if self.activities_list is None or self.activities_list == []:
            logger.warning("Still empty list of activities, so I can't do this!")
        else:
            self.first_seen_in_this_sample = float(self.activities_list[0]["secflow"]["relativeStart"])
            self.last_seen_in_this_sample = float(self.activities_list[-1]["secflow"]["relativeStart"]) + float(
                self.activities_list[-1]["secflow"]["duration"])

    def get_title(self):
        for activity in self.activities_list:
            if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
                return activity["event"]["title"]
            elif "behavior" in activity.keys() and activity["behavior"] != {}:
                return activity["behavior"]["title"]
            elif "destination" in activity.keys() and activity["destination"] != {}:
                return activity["destination"]["title"]
        return self.destination_and_port

    def get_description(self):
        for activity in self.activities_list:
            if "event" in activity.keys() and activity["event"] != {} and activity["event"] != "null":
                return activity["event"]["description"]
            elif "behavior" in activity.keys() and activity["behavior"] != {}:
                return activity["behavior"]["description"]
            elif "destination" in activity.keys() and activity["destination"] != {}:
                return activity["destination"]["description"]

    def get_total_score(self):
        score = 0
        for inference_data in self.associated_inferences.keys():
            score += self.associated_inferences[inference_data][1]
        return score

    def get_descriptions_as_string(self):
        descriptions = ""
        for inference_data in self.associated_inferences.keys():
            descriptions += self.associated_inferences[inference_data][0] + " "
        return descriptions
