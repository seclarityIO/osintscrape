"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import ipaddress
import json
import logging
import math
import re
import socket
import threading
from urllib.parse import urlparse

import requests

import constants
from destinationproperties import whois_analysis
from metadatascripts import retrieve_metadata

logger = logging.getLogger("Utilities")

"""Contains various utilities that are useful for checking connectivity and making sane decisions on domain
    reachability.
"""


def get_destination_from_link(link):
    destination = urlparse(link).netloc
    destination = destination.replace("[", "")
    destination = destination.replace("]", "")
    return destination


def get_destination_type(destination):
    """Determines if a destination is a domain or an IP address
    """
    try:
        if ipaddress.ip_address(destination):
            return "IP"
        else:
            return "domain"
    except:
        return "domain"


def create_safe_link(link):
    """Makes sure that any domain names are formatted with [] around . characters to avoid accidental clicks.
    """
    if "[.]" not in link:
        link = link.replace(".", "[.]")
    return link


def generate_sample_link_from_uuid(uuid):
    """Easy call to make a sample URL out of an incoming public or private UUID
    """
    link = "https://networksage.seclarity.io/"
    if len(uuid) == 100:  # public UUID length
        link += "public/"
    elif len(uuid) != 32:  # private UUID length
        return None
    link += "samples/" + uuid
    return link


def dest_without_port(destination):
    """ It is a common occurrence to want to go from a destination with a port (such as google.com:443) to just the
        destination name itself (such as google.com). This does that quickly
    """
    try:
        return destination[:destination.rfind(":")]
    except:
        return None


def validate_real_destination(link):
    """Not used in production. Beneficial for parsing links out of tweets and other places.
    """
    if "/" in link:
        dest = get_destination_from_link(link)
    else:
        dest = link
    # print("In validate_real_destination, link is", link)
    # print("And dest is", dest)
    if "@" in link and link.find("@") < link.find(dest):
        logger.info("This is probably an email address. Skipping.")
        return False
    dest_type = get_destination_type(dest)
    if not whois_analysis.has_whois_data(dest):
        if dest_type == "domain":
            if not destination_is_resolvable(dest):
                logger.info("No WHOIS and no DNS information, so "
                            + str(dest)
                            + " is probably not a real domain. Skipping."
                            )
                return False
            else:
                if not re.search("[a-zA-Z]", dest):
                    logger.info(
                        "Accidentally labeled some random floating-point number ("
                        + str(dest)
                        + ") as a domain. Skipping."
                    )
                    return False
        else:
            logger.info("No WHOIS for " + str(dest) + ", so this is probably not a real IP. Skipping.")
            return False
    return True


def dns_lookups_working():
    """Make sure that DNS lookups are actually working on this system
    """
    resolved = dns_forward_lookup("google.com")
    if resolved is None:
        return False
    else:
        for answer in resolved:
            ip = answer[4][0]
            if ip not in ["127.0.0.1", "::1"]:
                return True
        return False


def destination_is_resolvable(link):
    """Determine if a destination can be reached.
    """
    if "/" in link:
        dest = get_destination_from_link(link)
    else:
        dest = link
    resolved = dns_forward_lookup(dest)
    if resolved is None:
        return False
    else:
        for answer in resolved:
            ip = answer[4][0]
            if ip not in ["127.0.0.1", "::1"]:
                return True
        return False
    return True


def dns_forward_lookup(domain):
    """Perform a forward DNS lookup on a domain name
    """
    try:
        resolution = socket.getaddrinfo(domain, 0)
    except:  # name may no longer have a valid IP address
        return None
    return resolution


def lookup_ips_for_name(candidate_domain, destination_ip):
    """Determine if a domain name has IP addresses.
    """
    resolution = dns_forward_lookup(candidate_domain)
    if resolution is None:
        return False
    ip_addresses = []
    for answer in resolution:
        ip_addresses += [answer[4][0]]
    if destination_ip in ip_addresses:
        return True
    return False


def pretty_print_domain_age(age_as_timedelta):
    days = age_as_timedelta.days
    secs = age_as_timedelta.seconds
    if days < 1:
        return (" just "
                + str(secs // 3600)
                + " hours old when first seen"
                )
    elif days == 1:
        return (" just "
                + str(days)
                + " day old when first seen"
                )
    elif days < 7:
        return (" "
                + str(days)
                + " days old when first seen"
                )
    if days < 14:
        return (" approximately "
                + str(days // 7)
                + " week old when first seen"
                )
    elif days < 365:
        return (" approximately "
                + str(days // 7)
                + " weeks old when first seen"
                )
    elif days < 730:
        return (" approximately "
                + str(days // 365)
                + " year old when first seen"
                )
    elif days >= 730:
        return (" approximately "
                + str(days // 365)
                + " years old when first seen"
                )


def get_sample_details(uuid, endpoint, request_headers):
    """This function continually polls the NetworkSage appropriate API endpoint to see if our sample's details have
        been successfully processed. If it is successful, we return the results. If it is still processing, we keep
        polling. If it fails, we return None.
    """
    details_checking_timer = threading.Event()
    while not details_checking_timer.wait(5.0):  # check every 5 seconds
        result = requests.get(constants.SAMPLES_API_ENDPOINT
                              + uuid
                              + endpoint
                              , headers=request_headers
                              )
        try:
            current_state = json.loads(result.text)
            if current_state["error"]:
                details_checking_timer.set()
                return None
            result_data = current_state["body"]
            if result_data["status"] == "failed":
                details_checking_timer.set()
                return None
            if result_data["status"] == "generated":
                details_checking_timer.set()
                return json.loads(result_data[endpoint[1:]])
            if result_data["status"] == "processing":
                continue  # still working on processing
            else:
                logger.warning("Unknown state detected: " + str(result_data["status"]))
        except:
            logger.error("Something went wrong while fetching sample details.")
            return None


def had_error(response):
    """Quick error handling function to avoid code repetition.
    """
    if response.status_code != requests.codes.ok:
        logging.error("Error: " + str(response.text))
        return True
    json_data = json.loads(response.text)
    if json_data["error"]:
        logging.error("Error: " + str(json_data["body"]))
        return True
    return False


def get_subdomain_details_by_name(dest_and_port, api_key):
    """Returns a list of Destinations (see https://www.seclarity.io/resources/glossary/ for details) for valid
       subdomains of a given destination:port name when the destination is a domain. For any subdomain that does not
       correspond to a known Destination, a dictionary containing only that subdomain's name and port will be returned
       in the list. Note that this wrapper includes names for each subdomain, while the other destination calls do not.
    """
    destination = None
    request_headers = { "apikey": api_key }

    if ":" not in dest_and_port:
        print("Error: Must include a port for destination.")
        return None
    parts = dest_and_port.split(":")
    name = None
    try:
        if get_destination_type(parts[0]) == "domain":
            name = parts[0]
    except:
        return None
    if name is None:
        logger.error("Error: Must be a domain name.")
        return None

    subsets = name.split(".") # last one is the TLD or ccTLD
    subdomains = set()
    all_destinations = []
    if len(subsets) == 2: # it's just example.com, so no subdomains to process
        dest_dict = {"destinationName": dest_and_port}
        dest_details = retrieve_metadata.get_metadata_for_item("destination", dest_and_port, api_key)
        dest_details.update(dest_dict)
        all_destinations = [dest_details]
    else:
        for i in range(0, len(subsets)-1):
            try:
                subdomains.add(".".join(subsets[i:]) + ":" + parts[1])
            except:
                continue
        result = []

        session = requests.Session() # call all subdomains via one session
        for subdomain in subdomains:
            dest_dict = {"destinationName": subdomain}
            dest_details = retrieve_metadata.get_metadata_for_item("destination"
                                                                   , subdomain
                                                                   , api_key
                                                                   , session=session
                                                                   )
            #dest_details = get_destination_by_name(subdomain, session=session)
            dest_details.update(dest_dict)
            all_destinations += [dest_details]
    return all_destinations


def convert_size(size_bytes):
    """Convert bytes to human-readable strings
    """
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])
