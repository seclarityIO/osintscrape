"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import datetime
import logging
import pathlib
import pickle
import platform

import whois  # pip3 install python-whois from https://pypi.org/project/python-whois/

import activitygroup.activity_grouping

logger = logging.getLogger("WhoisAnalysis")


def collect_whois(destinations, fresh=False):
    """Collect WHOIS information for a list of destinations (domain or IP). If the fresh flag is passed in as True, it
        will perform a fresh WHOIS lookup regardless of whether we have cached results.
    """
    results = dict()
    for destination in destinations:
        if ":" in destination:
            destination_term = destination[:destination.rfind(":")]
        else:
            destination_term = destination
        try:
            if not fresh:
                logger.info("Checking to see if we have any cached WHOIS data for " + destination_term)
                results[destination_term] = retrieve_cached_results(destination_term)
                if results[destination_term] is None:
                    logger.info(
                        "Got cached WHOIS data of None for " + destination_term + ", so requesting a fresh lookup.")
                    whois_data = whois.whois(destination_term)
                    if whois_data is not None:
                        logger.info(
                            "Saving our fresh WHOIS lookup for " + destination_term + " since previously it was None.")
                        save_results_to_cache(destination_term, whois_data)
                        results[destination_term] = whois_data
                #logger.info("CACHED WHOIS Results: " + str(results[destination_term]))
            else:
                logger.info("Performing a fresh lookup for WHOIS results")
                results[destination_term] = whois.whois(destination_term)
                #logger.info("FRESH WHOIS Results: " + str(results[destination_term]))
        except:
            logger.warning("Failure occurred while trying to get WHOIS results.")
            results[destination_term] = None
    return results


def has_whois_data(destination):
    """Determines if a site has WHOIS. Checks our cache first to try to avoid too many WHOIS lookups.
    """
    logger.info("In has_whois_data --> Checking whois for -> " + destination)
    result = collect_whois([destination])  # first collect any cached results, if they exist
    if result is None:
        logger.info("No cached data for " + destination + " ... Trying a fresh copy")
        result = collect_whois([destination], fresh=True)  # then try a fresh copy if nothing useful in cache
    if result is None:
        logger.info("No cached data for " + destination + " with fresh=True")
        return False

    logger.info("whois data for " + destination + " isn't None")

    if destination not in result.keys():
        return False
    if result[destination] is None:
        return False
    try:
        if result[destination]["registrar"] is None:  # should always be there
            return False
    except:
        logger.warning("result[destination]['registrar'] is None ")
        try:
            if result[destination]["creation_date"] is None:
                return False
        except:
            return False
    logger.info("Returning true from has_whois_data for " + destination)
    return True


def get_root_domain_info(verdict_records, root_domain=None, organization_name=None):
    """For a passed in organization name, determine the root domain it belongs to from the set of domains in the
        destination records.
    """

    first_time = None
    full_domain = None
    try:
        for destination in verdict_records["destinations"]:
            if organization_name is not None:
                try:
                    org_data = verdict_records["destinations"][destination]["org_by_whois"]
                except:
                    org_data = None
                if org_data is not None:
                    if org_data == organization_name:
                        first_time = None
                        try:
                            root_domain = verdict_records["destinations"][destination]["root_domain_by_whois"]
                        except:
                            try:  #try to get the most likely root domain when WHOIS didn't produce one
                                root_domain = ".".join(destination.split(".")[-2:])
                            except:
                                root_domain = None
                        #root_domain = verdict_records["destinations"][destination]["root_domain_by_whois"]
                        ags = []
                        for dest_and_port in verdict_records["destinations"][destination]["full_destinations"]:
                            try:
                                ags += dest_and_port["activity_groups"]
                            except:
                                logger.info("Couldn't find activity group for destination " + destination)
                                continue
                        for g in ags:
                            first_time = g.first_seen_in_this_group
                            full_domain = g.destination_and_port
                            break
                        break
            elif root_domain is not None:
                try:
                    root_domain_by_whois = verdict_records["destinations"][destination]["root_domain_by_whois"]
                except:
                    try:  #try to get the most likely root domain when WHOIS didn't produce one
                        root_domain_by_whois = ".".join(destination.split(".")[-2:])
                    except:
                        root_domain_by_whois = None
                if root_domain_by_whois is not None:
                    if root_domain_by_whois == root_domain:
                        ags = []
                        for dest_and_port in verdict_records["destinations"][destination]["full_destinations"]:
                            try:
                                ags += dest_and_port["activity_groups"]
                            except:
                                logger.info("Couldn't find activity group for destination " + destination)
                                continue
                        for g in ags:
                            first_time = g.first_seen_in_this_group
                            full_domain = g.destination_and_port
                            break
                        break
    except:
        pass
    return (root_domain, first_time, full_domain)


def get_root_domain_by_whois(whois_record):
    """Given a WHOIS record, returns a lower-case version of the root domain (i.e. the domain in the domain_name field
        of a WHOIS record) to which the site belongs. Returns None if the information is missing.
    """
    root_domain = None
    if whois_record is not None and "domain_name" in whois_record.keys():
        try:
            if type(whois_record["domain_name"]) == list:
                root_domain = whois_record["domain_name"][0].lower()
            else:
                root_domain = whois_record["domain_name"].lower()
        except:
            logger.info("Something went wrong collecting WHOIS root domain name.")
    return root_domain


def get_root_domains(whois_results):
    """Returns a list of all root domains found in this sample.
    """
    all_roots = set()
    for dest in whois_results:
        all_roots.add(get_root_domain_by_whois(whois_results[dest]))
    roots = list(all_roots)
    try:
        roots.remove(None)
    except:
        pass  # None doesn't exist in list
    return list(roots)


def get_domain_age_by_whois(whois_record, to_captured=False, captured_datetime=None):
    """Given a WHOIS record, returns a datetime object for the domain. Returns None if the information is missing.
        If to_captured is True, use the captured_datetime to figure out how old it was upon capture.
    """
    age = None
    creation_date = None
    if whois_record is not None and "creation_date" in whois_record.keys():
        try:
            if type(whois_record["creation_date"]) == list:
                creation_date = whois_record["creation_date"][0]
            else:
                creation_date = whois_record["creation_date"]
        except:
            logger.info("Something went wrong collecting WHOIS record's age.")
    if creation_date is not None:
        if to_captured and captured_datetime is not None:
            age = captured_datetime - creation_date
        else:
            now = datetime.datetime.today()
            age = now - creation_date
    return age


def save_results_to_cache(destination, whois_data):
    """This occurs when we don't have cached WHOIS results and want to save some. Generally, we should cache when we
        don't AND when the results look fully-formed (i.e. we have an Org name that's not 'None').
    """
    if "org" in whois_data.keys() and whois_data["org"] is None:
        """We want an org's data (if it exists) or an equivalent field for other WHOIS formats (future work) to be
            populated before we save results, because otherwise we might have an intermittent failure that we're looking
            at where data comes back partially-populated or not populated at all.
        """
        return None
    if platform.system().lower() == "windows":
        whois_cache_dir = str(pathlib.PurePath("C:\\TEMP\\whois"))
        delimiter = "\\"
    else:
        whois_cache_dir = str(pathlib.PurePath("/tmp/whois"))
        delimiter = "/"
    pathlib.Path(whois_cache_dir).mkdir(parents=True, exist_ok=True)  # make sure it exists
    filename = (whois_cache_dir
                + delimiter
                + destination
                + ".pkl"
                )
    try:
        cache_file = open(filename, "wb")
        pickle.dump(whois_data, cache_file)
        logger.info("Successfully saved whois to cache.")
    except:
        logger.info("Failed to save whois to cache.")


def retrieve_cached_results(destination):
    """Retrieves WHOIS results that are cached and returns them to object format. If the results seem to indicate that
        the WHOIS information for the domain is expired, a new lookup should occur, be saved (if it's fully-formed), and
        then returned in place of the existing cache result.
    """
    get_fresh = False
    whois_data = None
    if platform.system().lower() == "windows":
        whois_cache_dir = str(pathlib.PurePath("C:\\TEMP\\whois"))
        delimiter = "\\"
    else:
        whois_cache_dir = str(pathlib.PurePath("/tmp/whois"))
        delimiter = "/"
    pathlib.Path(whois_cache_dir).mkdir(parents=True, exist_ok=True)  # make sure it exists
    try:
        filename = (whois_cache_dir
                    + delimiter
                    + destination
                    + ".pkl"
                    )
    except Exception as e:
        logger.info("Error: " + str(e))
        get_fresh = True
    try:
        cache_file = open(filename, "rb")
        whois_data = pickle.load(cache_file)
    except pickle.UnpicklingError as e:
        logger.info("Error unpickling: " + e)
        get_fresh = True
    except:
        get_fresh = True
    """Check to see if the WHOIS result has passed its expiration date. If so, request a fresh whois lookup and store
        it (if it looks okay).
    """
    now = datetime.datetime.today()

    if whois_data is not None and "expiration_date" in whois_data.keys():
        logger.info("Got cached WHOIS result.")
        # print("Existing (cached) whois data:", whois_data)
        if type(whois_data["expiration_date"]) == list:
            expiration = whois_data["expiration_date"][0]
        else:
            expiration = whois_data["expiration_date"]
        if expiration is None:
            get_fresh = True
        else:
            # print("Comparing", now, "to expiration", expiration)
            if now >= expiration:  # result has expired
                get_fresh = True
    else:
        get_fresh = True

    if get_fresh:
        result = collect_whois([destination], fresh=True)
        try:
            if "org" not in result[destination].keys() or result[destination]["org"] is not None:
                # reassign to whois_data variable so it's returned in place of stale record and save to cache
                whois_data = result[destination]
                #logger.info("For " + destination + ", we're saving WHOIS data of " + str(whois_data))
                save_results_to_cache(destination, whois_data)
            else:
                if whois_data is None:
                    whois_data = result[destination]  # we don't save it here, because the data doesn't look complete.
                    logger.info(
                        "Even though new WHOIS record doesn't look complete, we're using it because there is no old one!")
                    #logger.info("Aforementioned incomplete WHOIS record: " + str(whois_data))
                else:
                    logger.info("Using expired WHOIS record because new one looks broken!")
        except:
            logger.info("Using expired or partial WHOIS record because new one looks broken!")
            #logger.info("Aforementioned expired or partial WHOIS record: " + str(whois_data))
    return whois_data
