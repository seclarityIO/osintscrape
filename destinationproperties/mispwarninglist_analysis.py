"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import logging

from pymispwarninglists import WarningLists  # pip install pymispwarninglists

import utilities

logger = logging.getLogger("MispWarningListAnalysis")

def collect_matches(destinations):
    """Collect knowledge about any matches that have been found for the incoming destinations from MISP's warning lists
        (available for commercial use; found at https://github.com/MISP/misp-warninglists). If it's an IP address, we
        check for an exact match in any of the results of the slower exact-match warning list functionality (indicated
        by instantiating the WarningLists object with True).
    """
    results = dict()
    fast_warninglists = WarningLists()
    slow_warninglists = WarningLists(True)  # only used for IPs because they need an exact match from one of many CIDRs
    for destination in destinations:
        if ":" in destination:
            destination_term = destination[:destination.rfind(":")]
        else:
            destination_term = destination
        destination_type = utilities.get_destination_type(destination_term)
        if destination_type == "domain":
            warninglists = fast_warninglists
        else:
            warninglists = slow_warninglists
        try:
            logger.info(
                "Checking to see if we have any MISP Warning List data for " + destination_term + " or ." + destination_term)
            if destination_type == "domain":  # some lists prepend a dot to indicate all child domains, so check that too
                results[destination_term] = (warninglists.search(destination_term)
                                             + warninglists.search("." + destination_term)
                                             )
                """ These are matching in a way that causes issues that we don't want.
                if results[destination_term] == []:
                    # explicitly check the slow lists just in case, since they seem to match more often
                    logger.info("Explicitly checking slow MISP warning lists for domain "
                                 + destination_term
                                 + " because fast lists returned no results."
                                 )
                    results[destination_term] = (slow_warninglists.search(destination_term)
                                                 + slow_warninglists.search("."+destination_term)
                                                 )
                """
            else:  # IP addresses will have grabbed the slow lists (from above)
                logger.info("Checking slow MISP warning lists for IP address " + destination_term)
                results[destination_term] = warninglists.search(destination_term)
            if len(results[destination_term]) == 0:
                results[destination_term] = None
            else:
                logger.info("Got " + str(len(results[destination_term])) + " warning lists for " + destination_term)
        except:
            results[destination_term] = None
    return results
