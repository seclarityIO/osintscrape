"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import logging
import pathlib
import pickle
import platform

from analysis import analysis
from metadatascripts import retrieve_metadata

logger = logging.getLogger("EvidenceCollector")

"""This class is used to collect all information about a sample. It is passed around quite extensively.
"""


class EvidenceCollector():
    def __init__(self, networksage_sample_uuid=None):
        self.destination_data = dict()  # contains information about individual destinations in this sample
        self.sample_metadata = dict()  # contains metadata about the sample itself
        self.other_metadata = dict()  # contains other various metadata, including how to communicate with the user
        if networksage_sample_uuid is not None and len(networksage_sample_uuid) in [32, 100]:
            self.sample_metadata["uuid"] = networksage_sample_uuid
            self.sample_metadata["is_public"] = True if len(networksage_sample_uuid) == 100 else False
        else:
            self.sample_metadata["uuid"] = None

    def __getstate__(self):  # for proper pickling
        return self.__dict__

    def __setstate__(self, d):  # for proper unpickling
        self.__dict__ = d

    def collect_evidence(self, incoming_evidence, user_apikey, via_slack):
        """If we already have collected the evidence for this sample (i.e. in a different, recent function call), this
            will load that information from the cache and provide it to the caller for further analysis. If that is not
            the case, it will create all evidence for this sample.
        """
        evidence = self
        if "mode" in incoming_evidence.other_metadata.keys() and incoming_evidence.other_metadata[
            "mode"] == "destination_analysis":
            logger.info("This is Destination Analysis mode, so we're skipping any evidence collection")
            return incoming_evidence
        try:
            cached_evidence = self.retrieve_cached_results(
                evidence.sample_metadata["uuid"])  # we should now have a fully-populated version or None
            evidence = cached_evidence if cached_evidence is not None else evidence
        except:
            logger.info("No cached results were retrieved from evidence. Trying incoming_evidence.")
            try:
                cached_evidence = self.retrieve_cached_results(
                    incoming_evidence.sample_metadata["uuid"])  # we should now have a fully-populated version or None
                evidence = cached_evidence if cached_evidence is not None else incoming_evidence
            except:
                logger.info("No cached results were retrieved from incoming_evidence.")
        if evidence is None:
            logger.info("Creating a new evidence collector now.")
            evidence = EvidenceCollector()
        else:
            if "is_public" not in evidence.sample_metadata.keys():
                evidence.sample_metadata["is_public"] = True if len(evidence.sample_metadata["uuid"]) == 100 else False
            logger.info("Retrieved cached results for sample with UUID of "
                         + evidence.sample_metadata["uuid"]
                         )
        if via_slack:
            try:
                evidence.other_metadata["channel_id"] = incoming_evidence.other_metadata["channel_id"]
                evidence.other_metadata["msg_id"] = incoming_evidence.other_metadata["msg_id"]
            except:
                logger.info("Couldn't get Slack metadata, so setting via_slack to False.")
                via_slack = False
        if len(evidence.destination_data) == 0:  # we don't yet have evidence
            successful_retrieval = retrieve_metadata.gather_sample_metadata(evidence, user_apikey)
            if not successful_retrieval:
                return None
            verdict = analysis.analyze_all_evidence(evidence
                                                    , via_slack
                                                    )
            proposed_actions_dict = analysis.semifinalize_categorization_of_suspicious_activity(verdict)
            analysis.infuse_decisions_with_clustering(verdict, proposed_actions_dict, evidence.sample_metadata)
        else:
            logger.info("Using cached evidence from recent run to make decisions.")
        return evidence  # make sure we capture it

    def save_results_to_cache(self):
        """This occurs when we don't have cached results and want to save some. Generally, we should cache when we don't
            have any cached results.
        """
        logger.info("message=Saving results to cache")

        if platform.system().lower() == "windows":
            evidence_cache_dir = str(pathlib.PurePath("C:\\TEMP\\evidence"))
            delimiter = "\\"
        else:
            evidence_cache_dir = str(pathlib.PurePath("/tmp/evidence"))
            delimiter = "/"
        pathlib.Path(evidence_cache_dir).mkdir(parents=True, exist_ok=True)  # make sure it exists
        filename = (evidence_cache_dir
                    + delimiter
                    + self.sample_metadata["uuid"]
                    + ".pkl"
                    )
        try:
            cache_file = open(filename, "wb")
            pickle.dump(self, cache_file)
            logger.info("Successfully saved evidence to temporary cache.")
        except:
            logger.info("Failed to save evidence to cache.")

    def retrieve_cached_results(self, uuid):
        """Retrieves results that are cached and returns them to object format.
        """
        if platform.system().lower() == "windows":
            evidence_cache_dir = str(pathlib.PurePath("C:\\TEMP\\evidence"))
            delimiter = "\\"
        else:
            evidence_cache_dir = str(pathlib.PurePath("/tmp/evidence"))
            delimiter = "/"
        pathlib.Path(evidence_cache_dir).mkdir(parents=True, exist_ok=True)  # make sure it exists
        try:
            filename = (evidence_cache_dir
                        + delimiter
                        + uuid
                        + ".pkl"
                        )
        except:
            logger.info("Error: sample UUID is None.")
            return uuid
        try:
            cache_file = open(filename, "rb")
            evidence = pickle.load(cache_file)
        except pickle.UnpicklingError as e:
            logger.info("Error unpickling: " + e)
            return None
        except:
            return None
        logger.info("Retrieved cached evidence for current sample's UUID.")
        return evidence

    def delete_cached_results(self):
        """Cached results are only supposed to stay around for API calls that are happening nearly simultaneously. Once
            finished, the cache should be removed.
        """
        try:
            logger.info("About to delete evidence cache.")
            if platform.system().lower() == "windows":
                evidence_cache_dir = str(pathlib.PurePath("C:\\TEMP\\evidence"))
                delimiter = "\\"
            else:
                evidence_cache_dir = str(pathlib.PurePath("/tmp/evidence"))
                delimiter = "/"
            try:
                filepath = pathlib.Path(evidence_cache_dir
                                        + delimiter
                                        + self.sample_metadata["uuid"]
                                        + ".pkl"
                                        )
                filepath.unlink(missing_ok=True)
            except:
                logger.info("Evidence cache file already deleted.")
        except:
            logger.info("Something nonfatal failed while trying to delete cached evidence.")
