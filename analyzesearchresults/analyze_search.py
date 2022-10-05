"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import ast
import ipaddress
import logging
import numpy
import pathlib
import pickle
import platform
import re
import statistics
from urllib.parse import urlparse

import tldextract

from analyzesearchresults import analyzed_data
# from greynoise import GreyNoise #RIOT data set access -- currently not used, but likely will be useful on IPs
from analyzesearchresults import search_results

logger = logging.getLogger("AnalyzeSearch")

"""This module takes raw search results (either from a fresh Google search or a cached result) for a domain or IP
    address and attempts to interpret them in the way that a security analyst would. This is predominantly based on my
    10 years of experience in the field. The goal is to come up with a category, risk, rough confidence
    level/score, and the text to show the user from this content. Note that this is only part of our final verdict for a
    site when we have a sample being analyzed. Details:
    1. Category
        This will capture the category (specifically, when possible) of the incoming site. Things that are often seen
        from this include Generic Malicious Site, Benign Site, Tracking/Analytics Site, URL Shortener, New Business
        Site, and so on.
    2. Risk
        This captures knowledge of how likely we think something is risky within a particular category. This uses
        qualifiers like "Potentially," "Likely," and "Known" to help convey likelihood.
    3. Confidence Level/Score
        This captures our overall score (which combines the scores of all individual search results we've analyzed) for
        a site. 0-4 is reserved for things that are in the range of Benign (where 0 is a much more confident belief of
        benign than 4). 5-10 is reserved for things that are in the range of Malicious (where 5 is not certain at all,
        and 10 is absolutely certain).
    4. Text
        This captures the data from our search results (and from our interpretation of the results) that we think is the
        most informative for a user (for example, to understand why we selected our current category/risk/confidence).
        The data we share as interpretation is intended to provide users with learning opportunities, while the sharing
        of search results is for them to understand more precisely how we came to a conclusion, when relevant.

    Finally, there will ultimately need to be a way to turn this into an ML model that we can input relevant industry
    reports and content (for vocabulary), take feedback (FPs, FNs) from users, and so on. I had previously started
    building this functionality out , but I found it to be too slow (~5 seconds per input site) and far less useful than
    what I could create by encoding my experiences as code. A blend of both is ideal in the long term.
"""

"""Define some things that should be available throughout this module
"""

myAPIKey = ""
# The regular expressions below capture different infrequently-changing ways that results appear.
# Regexes for determining risk
security_results_terms = re.compile(
    r"mal(ware|icious)|( any\.run)|virus|scam|threat([^crowd])|how to remove|(#?phish)|reputation (ana|look)|blacklist|crx|( ioc|ioc[s]?( |:))"
    , flags=re.IGNORECASE)  # for the search result title
known_malicious_terms = re.compile(
    r"#phishing|[^(is)]:? malicious( activity|[^(\?| a-z)])|risk malware( |\.)|( |\")C2(Server|)|( |\")Beacon((s|ing)(\.|:| to| ))|([^(25)] |\")IOCs?| Cobalt(| )Strike|Phishing site detected"
    , flags=re.IGNORECASE)  # for the search result snippet
likely_security_results = re.compile(r"phishing.*\.(txt|csv|md|yaml)(|\/)$"
    , flags=re.IGNORECASE) # for links
pup_results_terms = re.compile(r"virus |remov(e|al|ing)| adware| ads | popup "
                               , flags=re.IGNORECASE)
doc_common_vector_terms = re.compile(r"\.(doc|pdf|xls|dll)"
                                     , flags=re.IGNORECASE)
phishing_common_terms = re.compile(r"[^(for)] Phishing"
                                   , flags=re.IGNORECASE)
impact_common_terms = re.compile(r"\.(exe|dmg|py|sh|vbs|ps1)"
                                 , flags=re.IGNORECASE)
browser_executables = re.compile(r"(firefox|chrome|safari)\.(exe|dmg)"
                                 , flags=re.IGNORECASE)
site_rank_terms = re.compile(r"statistics|valuation|rank|Registered (by|for) Date|Domain Registrations On"
                             , flags=re.IGNORECASE)
twitter_as_url = re.compile(r"h(tt|xx)p(s|)://(mobile\.|)twitter\.com\/.*\/status\/"
                            , flags=re.IGNORECASE)
related_site_terms = re.compile(r"Ownership Information and DNS Records")

# Regexes for identifying categories
tracking_identifier_sites = re.compile(r"https:\/\/((confection\.io)|whotracks\.me)\/")
consumer_business_terms = re.compile(
    r"grubhub|yelp|doordash|allmenus|tripadvisor|wixrestaurants|menupix|untappd|deviantart"
    , flags=re.IGNORECASE)  # use only on links, not titles
url_shortener_terms = re.compile(r"( |^)(url|link) shorten|short url"
                                 , flags=re.IGNORECASE)  # use on titles
trustworthy_threat_report_sites = re.compile(
    r"^https:\/\/((((blog\.group-ib)|xxxxxxx)\.com($|\/))|(www\.fortiguard\.com\/resources\/threat\-brief)|(www\.trendmicro\.com\/en_us\/research\/)|(intel471\.com\/blog\/))"
    , flags=re.IGNORECASE)  # use only on links
legit_big_business_sites = re.compile(
    r"https://((www\.linkedin\.com/company)|play\.google\.com/store/apps|apps\.apple\.com)/")

# other useful regexes
possible_domain = re.compile(r"([a-zA-Z]+[a-zA-Z0-9\-]*\.){1,}[a-z]{2,10}"
                             , flags=re.IGNORECASE)  # captures strings that may be domain names
domain_as_url_regex = r"http(s|)://([a-zA-Z]+[a-zA-Z0-9\-]*\.)*{}"


def analyze_search_results(result_object, input_type, was_secondary_analysis=False):
    """Analyzes search results to determine the category, risk, confidence level, and text to return to a user.
        Categories will grow with time to be more intelligent.
    """

    # stuff from our ML content that is currently turned off
    # print("Topics that may help us make better decisions:")
    # for key in result_object.inferred_topics.keys():
    #    print("\t"+str(key)+".\t"+result_object.inferred_topics[key]+"\n")

    # create a new object to store results
    analysis_results = analyzed_data.AnalyzedData(result_object.search_term, was_secondary_analysis)

    """ Begin by understanding how many total results exist """
    if result_object.total_results == -1:
        # we didn't find results, but didn't explicitly capture that (because Google changed their setup, for example)
        result_object.total_results = 0
    else:
        analysis_results.total_results = result_object.total_results
    highlevel_analysis(input_type, result_object, analysis_results)
    interpret_top_results(input_type, result_object, analysis_results)

    if input_type == "domain":
        if not are_results_relevant(result_object, analysis_results, was_secondary_analysis):
            # here's the first place we might decide to stop early, because results were irrelevant
            return analysis_results
    calculate_initial_score(analysis_results)

    if input_type == "IP":
        analysis_results.final_text += (analysis_results.evidence["totalResults"][0][0]
                                        + " "
                                        )
    else:
        analysis_results.final_text += (analysis_results.evidence["totalResults"][0][0]
                                        + " "
                                        )
    if is_analytics(analysis_results):
        return analysis_results  # short-circuit
    if analysis_results.score >= 5:  # scores of 5 to 10 are more than likely malicious
        lm_result = determine_if_likely_malicious(result_object, analysis_results, input_type)
    else:
        determine_if_likely_benign(result_object, analysis_results)
    analysis_results.score = min(10, analysis_results.score)  # high score is 10
    if analysis_results.has_secondary_analysis:
        """A secondary analysis occurs when we have an IP address (or something that is essentially an IP) that -- when
            searched -- seems to correlate with just one domain. At that time, we re-search for the domain we found.
        """
        try:
            if lm_result is not None:
                domain_analysis_results = lm_result
                if domain_analysis_results.was_secondary_analysis:  # WAS the domain analysis that came from an input IP
                    domain_analysis_results.score = min(10, domain_analysis_results.score)  # high score is 10
                    if not "Malicious" in domain_analysis_results.category:
                        analysis_results.final_text += ("Originally, we believed "
                                                        + analysis_results.term
                                                        + " to be Malicious. However, because it seems to be associated with just one actual domain ("
                                                        + domain_analysis_results.term
                                                        + ") that ISN'T malicious, we now believe that there isn't risk. The ORIGINAL results for the IP address itself are as follows:\n"
                                                        + analysis_results.final_text
                                                        )
                        analysis_results.final_text += (
                                "\nHowever, as stated before, NetworkSage now believes that there is not risk. Details for "
                                + domain_analysis_results.term
                                + " are as follows:\n"
                        )
                        analysis_results.category = domain_analysis_results.category
                        analysis_results.risk = domain_analysis_results.risk
                        analysis_results.final_text += domain_analysis_results.final_text
                    else:  # we actually did believe it to be malicious
                        analysis_results.final_text += ("Originally, we believed "
                                                        + analysis_results.term
                                                        + " to be Malicious. However, because it seems to be associated with one actual domain ("
                                                        + domain_analysis_results.term
                                                        + "), we wanted to check that too. The ORIGINAL results for the IP address itself are as follows:\n"
                                                        + analysis_results.final_text
                                                        )
                        analysis_results.final_text += ("\nDetails for "
                                                        + domain_analysis_results.term
                                                        + " are as follows:\n"
                                                        )
                        analysis_results.category = domain_analysis_results.category
                        analysis_results.risk = domain_analysis_results.risk
                        analysis_results.final_text += domain_analysis_results.final_text
        except:
            logger.info("We thought we had a secondary search analysis, but we didn't.")
    return analysis_results


def highlevel_analysis(input_type, result_object, analysis_results):
    """Gather some initial, high-level information from our search results. For any analysis we do, we capture a score
        (from 0 to 10, lower being more benign) that helps us to determine whether we think something is malicious. Each
        time something matches our logic, we add it to our evidence dictionary with a score (0-10) to help influence the
        final score for this site.
    """

    if input_type == "IP":
        """ Check GreyNoise"s RIOT data set -- currently turned off
        #session = GreyNoise(api_key=myAPIKey)
        quick_response = session.quick(result_object.search_term)
        for data in quick_response:
            if data["noise"]:
                context_response = session.ip(result_object.search_term)
                tags_response = session.metadata()
                print("Context Response:", context_response)
                print("Tags Response:", tags_response)
            if data["riot"]:
                riot_response = session.riot(result_object.search_term)
                print("RIOT Response:", riot_response)
                analysis_results.risk = "Benign"
                analysis_results.score = int(riot_response["trust_level"])
                analysis_results.category = riot_response["category"]
                analysis_results.final_text += (riot_response["name"]
                                                + " is "
                                                + riot_response["explanation"][0].lower()
                                                + riot_response["explanation"][1:]
                                                + " "
                                                )
                analysis_results.has_riot = True
            else:
                continue
        """

        if result_object.total_results == 0:
            analysis_results.evidence["totalResults"] += [
                ("No results when searched, which (on its own) is highly suspicious."
                 , 10)
            ]
        elif result_object.total_results > 25:
            analysis_results.evidence["totalResults"] += [
                (
                    "There are a relatively high number of results, which may indicate that the IP serves many domains of varying trust levels."
                    , 5)
            ]
            analysis_results.category = "Shared Server"
        else:  # 1 to 25 results
            analysis_results.evidence["totalResults"] += [
                (
                    "There are few results when searched, which may indicate that this IP is associated with just one domain (or is an actual site)."
                    , 5)
            ]
            analysis_results.category = "Dedicated Server"
    else:  # domain logic, since type can only be IP or domain
        # grab topic info and prep it
        topic_info = ""
        if analysis_results.possible_topic is not None:
            try:
                #print("Possible topic data:", analysis_results.possible_topic)
                if analysis_results.possible_topic[1] > 1:
                    topic_info = (" While attempting to identify the topic of these results, we noticed that the "
                        + "most-repeated word (seen "
                        + str(analysis_results.possible_topic[1])
                        + " times in the top results) is "
                        + analysis_results.possible_topic[0]
                        + "."
                    )
            except:
                pass
        # First, interpret the number of results to understand its effect.
        if result_object.total_results == 0:
            analysis_results.evidence["totalResults"] += [
                ("No results when searched, which is highly suspicious."
                 , 10)
            ]
        elif 0 < result_object.total_results <= 10:
            # if none of the results seem to actually be for this domain, disregard this step...
            analysis_results.evidence["totalResults"] += [
                ("Only "
                 + str(result_object.total_results)
                 + " results, which is an extremely low number. This either indicates that the site is wildly unpopular "
                 + "(and therefore probably uninteresting) or it is a potentially unknown security threat."
                 + topic_info
                 , 8)
            ]
            try:
                link = str(result_object.top_results[1][1])  # grab link from top result, if it exists.
                if re.findall(r"^https:\/\/urlhaus\.abuse\.ch", link):
                    analysis_results.evidence["totalResults"] += [
                        (
                            "The TOP result when searched is from a site that tries to capture domains that are being abused. This is highly suspicious."
                            , 10)
                    ]
                    analysis_results.evidence["securityThreat"] += [
                        (link
                         , 10)
                    ]
                    analysis_results.first_security_threat = 1
                elif re.findall(r"^https:\/\/urlscan\.io", link):
                    analysis_results.evidence["totalResults"] += [
                        (
                            "The TOP result when searched is from a site that tries to automatically identify the behavior of a site. This is suspicious."
                            , 6)
                    ]
                    analysis_results.evidence["securityThreat"] += [
                        (link
                         , 6)
                    ]
                    analysis_results.first_security_threat = 1
            except:
                pass
        elif result_object.total_results <= 2000 and result_object.total_results > 10:
            analysis_results.evidence["totalResults"] += [
                ("There are "
                 + str(result_object.total_results)
                 + " total results for this site, which is a relatively low number to see when searching the Internet "
                 + "for a specific site. This can indicate that the site is not well known."
                 + topic_info
                 , 7)
            ]
        elif result_object.total_results < 10000 and result_object.total_results > 2000:
            analysis_results.evidence["totalResults"] += [
                ("There are "
                 + str(result_object.total_results)
                 + " total results for this site. Sites with many results (like this one) are often not interesting from a security perspective."
                 , 2)
            ]
        else:  # at least 10k results
            analysis_results.evidence["totalResults"] += [
                ("There are "
                 + str(result_object.total_results)
                 + " total results for this site, which is a considerably high number. The likelihood that this site is interesting from a security perspective is quite low."
                 , 0)
            ]
        """ We no longer have access to advertisements, so this must be excluded.
        # Next, capture whether or not we have advertisements for the site.
        if result_object.ads_text == "":
            analysis_results.evidence["advertisements"] += [
                    ("There are no advertisements, which usually means that the site isn't about a topic with a broad customer base."
                    , 6)
                ]
        else:
            # make links in ads unclickable
            result_object.ads_text = result_object.ads_text.replace("http", "hxxp")
            result_object.ads_text = result_object.ads_text.replace("HTTP", "HXXP")
            if result_object.total_results < 2000:
                analysis_results.evidence["advertisements"] += [
                        ("The existence of ads coupled with a low number of search results means that the site is likely related to something popular. This could mean that the site is attempting to impersonate a popular site through typosquatting or other impersonation techniques. The actual advertising text is:\n"
                        + "\t"
                        + result_object.ads_text
                        + "\n"
                        , 3)
                    ]
            else:
                analysis_results.evidence["advertisements"] += [
                        ("The existence of ads means that the site is likely related to something popular. Moreover, it could actually mean that the site is not malicious, but rather may be an Attack Vector. The actual advertising text is:\n"
                        + "\t"
                        + result_object.ads_text
                        + "\n"
                        , 3)
                    ]
        """


def get_possible_topic(top_results, search_term):
    """Attempts to perform a lightweight analysis of the top term.
    """
    words_by_frequency = dict()
    excluded_words = [
        "of",
        "the",
        "ip",
        "address",
        "range",
        "geolocation",
        "lookup",
        "and",
        "com",
        "by"
    ]
    for res in top_results:
        title = str(top_results[res][0])
        words = [chunk for chunk in re.split("[\.\-\(\)\\\/ ]", title) if chunk]
        for word in words:
            word = word.lower()
            if word in words_by_frequency.keys():
                words_by_frequency[word] += 1
            else:
                if word not in excluded_words and re.search(r"[a-z]+", word) is not None:
                    words_by_frequency[word] = 1
    sorted_words = [(k, v) for k, v in sorted(words_by_frequency.items(), key=lambda x: x[1], reverse=True)]
    all_vals = numpy.array([v for v in words_by_frequency.values()])
    try:
        high_outlier_min = numpy.quantile(all_vals, 0.99)
    except:
        return None
    for word_stats in sorted_words:
        if word_stats[1] >= high_outlier_min:
            return word_stats
        else:
            break # since we're already sorted, there shouldn't be more


def interpret_top_results(input_type, result_object, analysis_results):
    """We specifically keep up to the top 10 search results for a searched term, because those (if Google is doing its
        job) are the most relevant results (how frequently do you look past the first page of search results?). We
        use the information contained within the link, title, and text snippet to influence what we think of this
        searched term (which should either be a domain or an IP address). This is where the meat of our analysis logic
        is called. Each time something matches our logic, we add it to our evidence dictionary with a score (0-10) to
        help influence the final score for this site.
    """
    # Regex to prepare results for searching for names
    related_domain_for_ip_text_snippet_terms = re.compile(r"( |<em>){}".format(result_object.search_term))

    analysis_results.possible_topic = get_possible_topic(result_object.top_results, result_object.search_term)
    result_count = 0
    for res in result_object.top_results:
        result_count += 1
        if result_count == 1:
            analysis_results.top_result = result_object.top_results[res]
        title = str(result_object.top_results[res][0])  # str to handle special characters (foreign languages, etc...)
        link = str(result_object.top_results[res][1])
        text_snippet = str(result_object.top_results[res][2])

        if input_type == "IP":
            if re.findall(related_domain_for_ip_text_snippet_terms, text_snippet):
                # look for possible domain names within the returned text snippet from a result
                domain_candidate = re.search(possible_domain
                                             , text_snippet
                                             )
                if domain_candidate is not None:
                    domain_split = tldextract.extract(domain_candidate[0])
                    domain = ".".join(part for part in domain_split if part)
                    if re.search(impact_common_terms, domain) and not re.search(browser_executables, domain):
                        filename = domain
                        analysis_results.evidence["potentialImpact"] += [(text_snippet, 10)]
                    if not re.search(r"(in\-addr\.arpa(|\.))$", domain):
                        analysis_results.evidence["domainForIP"] += [(domain, 5)]
            if re.findall(r"> ([a-zA-Z]+[a-zA-Z0-9\-]*\.){1,}[a-z]{2,10}", title):  # search the title too
                domain_candidate = re.search(possible_domain
                                             , title
                                             )
                if domain_candidate is not None:
                    domain_split = tldextract.extract(domain_candidate[0])
                    domain = ".".join(part for part in domain_split if part)
                    # make sure we're not accidentally taking the name of the site that has results for this domain
                    domain_as_url = re.compile(domain_as_url_regex.format(domain)
                                               , flags=re.IGNORECASE
                                               )
                    if not re.search(domain_as_url, link):
                        if re.search(impact_common_terms, domain) and not re.search(browser_executables, domain):
                            filename = domain
                            analysis_results.evidence["potentialImpact"] += [(filename, 10)]
                        if not re.search(r"(in\-addr\.arpa(|\.))$", domain):
                            analysis_results.evidence["domainForIP"] += [(domain, 5)]
                            analysis_results.domains_mentioned_in_security_results.add(domain.lower())
        if result_count == 1 and text_snippet in ["None", ""]:  # first result is potentially an empty "shell"
            if re.search(r"^((http(|s)://)|){}$".format(title), link):
                # it is in fact a shell
                if result_object.total_results <= 2000:
                    analysis_results.evidence["pageHasNoTextSnippet"] += [(title, 9)]
        if input_type == "domain" and not analysis_results.referenced_in_results:
            parts = result_object.search_term.split(".")
            domain_formats = [result_object.search_term, "[.]".join(parts)]  # create 2 common domain formats seen
            if (any(domain in link for domain in domain_formats)
                    or any(domain in title for domain in domain_formats)
                    or any(domain in text_snippet for domain in domain_formats)
            ):
                analysis_results.referenced_in_results = True  # needs to be smarter, but trying to exclude irrelevant results
        if re.findall(tracking_identifier_sites, link):
            interpret_tracking_result(analysis_results, link, title)
        if re.findall(trustworthy_threat_report_sites, link):
            # trustworthy threat report sites in search results should be a strong indicator of maliciousness
            analysis_results.evidence["securityThreat"] += [(title, 10)]
        if (re.findall(security_results_terms, title)
                or re.findall(known_malicious_terms, text_snippet)
                or re.findall(likely_security_results, link)
        ):
            interpret_possible_malicious_result(analysis_results, result_object, link, title, text_snippet,
                                                result_count)
            interpret_possible_attackvector_result(analysis_results, result_object, title, text_snippet)
        elif re.findall(pup_results_terms, title):  # PUP == Potentially Unwanted Program
            analysis_results.evidence["pupThreat"] += [(title, 7)]
        if result_object.total_results < 2000:
            domain_is_link = re.compile(
                r"http(s|)://([a-zA-Z]+[a-zA-Z0-9\-]*\.)*{}($|/)".format(result_object.search_term)
                , flags=re.IGNORECASE
            )
            domain = None
            if re.search(domain_is_link, link):
                domain = link
            if re.findall(site_rank_terms, title):
                analysis_results.evidence["lowRelevanceTopResults"] += [(title, 7)]
            """When the domain is a significant number of the first set of links, it's more likely to be non-malicious.
                However, if its first search result is completely empty, then it's more likely malicious (because this
                seems to correlate with an attacker trying to impersonate a real site and rank a bunch of links highly).
            """
            if domain and not analysis_results.evidence["pageHasNoTextSnippet"]:
                analysis_results.evidence["business"] += [(title, 4)]
            if result_object.total_results <= 10 and result_object.total_results > 0:
                if re.search(twitter_as_url, link):  # has twitter:
                    if "Twitter statuses" not in analysis_results.final_text:
                        analysis_results.final_text += "When few results exist and the results that exist are Twitter statuses, it is much more likely that the domain is malicious. "
                    analysis_results.evidence["securityThreat"] += [(title, 6)]
                    if analysis_results.first_security_threat == -1:  # only capture first security threat if we haven't seen one yet
                        analysis_results.first_security_threat = result_count
        if re.findall(consumer_business_terms, link):
            analysis_results.evidence["business"] += [(title, 0)]
        if re.findall(legit_big_business_sites, link):
            analysis_results.evidence["business"] += [(title, 0)]
            analysis_results.is_big_business = True
        if re.findall(url_shortener_terms, title):
            analysis_results.evidence["urlShortener"] += [(title, 2)]


def are_results_relevant(result_object, analysis_results, was_secondary_analysis):
    """Google is of course based on machine learning and algorithms to be fast enough to support everyone querying it,
        so it can't be perfect. Scenarios I'm aware of that attackers leverage (and that we're attempting to handle):
            1. non-descript domains return useless results
            2. short domains return useless results
            3. domains that attempt to impersonate legitimate brands often return results (and advertising!) for that
               brand
        We try to capture when this is happening and alert the user to it. This means that sometimes we'll come through
        this function and decide to short-circuit without doing the remaining analysis in this module, because we'd be
        making decisions on incorrect data (which would benefit the attacker).
    """
    if not analysis_results.referenced_in_results:
        if 0 < analysis_results.total_results <= 10:
            analysis_results.final_text += "Though none of the search results specifically referenced this domain by name, the fact that there are very few results leads us to believe that it is still interesting. "
    return True


def calculate_initial_score(analysis_results):
    """Once we've done our analysis, calculate the average score across all of the scores provided. This will be
        subjected to more scrutiny in later post-processing steps.
    """
    for searchTopic in analysis_results.evidence.keys():
        for item in analysis_results.evidence[searchTopic]:
            if item is not []:
                analysis_results.all_scores += [item[1]]  # scores are captured in the second position of each tuple
            else:
                pass
    analysis_results.score = int(statistics.mean(analysis_results.all_scores))
    analysis_results.risk = ""


def interpret_possible_attackvector_result(analysis_results, result_object, title, text_snippet):
    """Determine if we have any evidence to indicate the result is pointing towards this site being an Attack Vector.
    """
    if re.findall(doc_common_vector_terms, title):
        if result_object.total_results >= 2000:
            analysis_results.evidence["potentialVector"] += [(title, 3)]
        else:
            analysis_results.evidence["potentialVector"] += [(title, 10)]
    if (re.findall(doc_common_vector_terms, text_snippet)
            or re.findall(phishing_common_terms, text_snippet)
    ):
        if result_object.total_results >= 2000:
            analysis_results.evidence["potentialVector"] += [(text_snippet, 3)]
        else:
            analysis_results.evidence["potentialVector"] += [(text_snippet, 10)]


def interpret_possible_malicious_result(analysis_results, result_object, link, title, text_snippet, result_count):
    """At this point, we are looking at a result that SEEMS to indicate that there is some maliciousness associated with
        the site we're analyzing. Because it is a big error to give the user the wrong information (in either direction),
        the goal of this function is to be more confident that this search result either is or is not an indicator that
        the site is malicious.
    """
    if (re.findall(known_malicious_terms, text_snippet)
            or re.findall(known_malicious_terms, title)
            or re.findall(likely_security_results, link)
    ):
        # if there's a site in this and it doesn't match (closely enough) the site we're passing in, don't mark as known malicious
        domain_candidate_title = re.search(possible_domain
                                           , title
                                           )
        if domain_candidate_title is not None:
            enhance_maliciousness_specificity(analysis_results
                                              , result_object
                                              , domain_candidate_title
                                              , link
                                              , title
                                              )
        domain_candidate_textsnippet = re.search(possible_domain
                                                 , text_snippet
                                                 )
        if domain_candidate_textsnippet is not None:
            enhance_maliciousness_specificity(analysis_results
                                              , result_object
                                              , domain_candidate_textsnippet
                                              , link
                                              , text_snippet
                                              )
        if not domain_candidate_title and not domain_candidate_textsnippet:  # capture mal when NO DOMAIN in the result name
            if title not in analysis_results.evidence["potentialImpact"]:
                analysis_results.evidence["securityThreat"] += [(title, 10)]
        elif domain_candidate_title or domain_candidate_textsnippet:
            analysis_results.evidence["securityThreat"] += [
                (title, 6)]  # we're far less sure that this is related here...
        if analysis_results.first_security_threat == -1:
            analysis_results.first_security_threat = result_count
    elif re.findall(pup_results_terms, title):
        analysis_results.evidence["pupThreat"] += [(title, 7)]
    else:
        analysis_results.evidence["securityThreat"] += [(title, 5)]
        if analysis_results.first_security_threat == -1:
            analysis_results.first_security_threat = result_count
            # we found security terms in the results, which at least means that other people have seen this site and have come across it in places where they think it could be security-relevant.


def enhance_maliciousness_specificity(analysis_results, result_object, candidate, link, input_data):
    """When we believe we have a result that tells us the site is malicious, try to be more precise with the information
        we provide the user whenever possible.
    """
    domain_split = tldextract.extract(candidate[0])
    domain = ".".join(part for part in domain_split if part)
    domain.lower()
    # make sure we're not accidentally taking the name of the site that has results for this domain
    domain_as_url = re.compile(domain_as_url_regex.format(domain)
                               , flags=re.IGNORECASE
                               )
    if not re.search(domain_as_url, link):
        if (re.search(impact_common_terms, domain)
                and not re.search(browser_executables, domain)
        ):
            analysis_results.evidence["potentialImpact"] += [(input_data, 10)]
        else:
            analysis_results.domains_mentioned_in_security_results.add(domain.lower())
            if result_object.search_term in domain:  # it's a substring
                analysis_results.evidence["securityThreat"] += [(input_data, 10)]


def interpret_tracking_result(analysis_results, link, title):
    """When we encounter search results that seem to indicate that a destination is a tracking or analytics site (which
       is a common confusion and time waster for analysts [especially early career ones]), we should provide that
       information to them so that they don't waste their precious time
    """
    if link.startswith("https://confection.io/"):  # this is a cookie and tracking identification site
        title_tracker = title.split(" ")[0]
        if title_tracker == analysis_results.term:
            analysis_results.evidence["trackingSite"] += [(title, 0)]
            analysis_results.should_label_destination = True
            capture_tracking_details(analysis_results, link)
        else:
            analysis_results.evidence["trackingSite"] += [(title, 2)]
            analysis_results.final_text += "This Destination has results that lead us to believe that it is related to analytics or tracking. "
            analysis_results.print_top_results = True
    elif link.startswith("https://whotracks.me/trackers/"):
        try:
            link_trackername = link.split("/")[-1].split(".")[0].capitalize() + "'s tracking"
        except:
            link_trackername = "known tracking"
        analysis_results.evidence["trackingSite"] += [(title, 0)]
        analysis_results.print_top_results = True
        label_name = link_trackername + " site"

        analysis_results.title = label_name
        analysis_results.final_text = ("This Destination is "
                                       + label_name
                                       + ". While this kind of tracking may be undesired, they are generally not security threats. "
                                       )


def capture_tracking_details(analysis_results, link):
    """Grab the details that we want to include with our response to the user when it's a tracking site.
    """
    term_dom = urlparse("https://" + analysis_results.term).hostname
    dsplit = term_dom.split(".")
    tracking_company = ".".join(dsplit[-2:-1]).capitalize()
    type_path = urlparse(link).path
    tsplit = type_path.split("/")
    ttype_raw = tsplit[1][:len(tsplit[1]) - 1].title()  # remove plural and capitalize
    tracking_type = " ".join(ttype_raw.split("-"))
    label_name = tracking_company + "'s Tracking "
    if tracking_type == "Tracker":
        label_name += "Site"
    else:
        label_name += tracking_type + " Site"
    analysis_results.title = label_name
    analysis_results.final_text = ("This Destination is "
                                   + label_name
                                   + ". While this kind of tracking may be undesired, they are generally not security threats. "
                                   )
    if tracking_type.startswith("Tag"):
        analysis_results.final_text += "Note that there have been cases in the past where attackers have compromised websites using tagging platforms and changed the tag IDs to point to less-controlled ad platforms, where they then served malicious ads. "


def is_analytics(analysis_results):
    """If this looks like a site associated with analytics or tracking, it's probably not interesting and should have
        the rest of the logic short-circuited.
    """
    if len(analysis_results.evidence["trackingSite"]) > 0:
        if analysis_results.evidence["trackingSite"][0][1] == 0:
            analysis_results.category = "Analytics/Tracking Site"
            analysis_results.risk = "Benign"
            analysis_results.final_text += "This site has been identified as a tracking or analytics site. It is very likely uninteresting from a security perspective. "
            analysis_results.score = 1
            return True
        logger.info("Site may be related to analytics, but we decided not to label it like that. Analytics results: "
                     + str(analysis_results.evidence["trackingSite"])
                     )
        # Otherwise we think it's related to analytics, but aren't sure.
    return False


def determine_if_likely_malicious(result_object, analysis_results, input_type):
    """One of the most important things we can do is avoid labeling activity as malicious that gets "caught in the
        crossfires" of malicious things, and only label things as malicious that are more than likely to truly be.
    """
    if analysis_results.category == "":
        analysis_results.category = "Generic Malicious Site"
    if analysis_results.risk == "":
        analysis_results.risk = "Potentially Malicious"
    num_security_threat = len(analysis_results.evidence["securityThreat"])
    num_pup_threat = len(analysis_results.evidence["pupThreat"])
    num_vector = len(analysis_results.evidence["potentialVector"])
    num_impact = len(analysis_results.evidence["potentialImpact"])
    total_risk_count = num_security_threat + num_pup_threat + num_vector + num_impact
    if not analysis_results.likely_seo_attack:
        if total_risk_count < 4 and result_object.total_results >= 10000:
            analysis_results.category = "Common Site"
            analysis_results.risk = "Likely Benign"
            analysis_results.final_text += "While there were some results that indicated that this site has been analyzed in security tools, the overall number of results strongly suggest that this site is actually uninteresting from a security perspective. "
            analysis_results.score = 3
            analysis_results.print_top_results = True
        elif total_risk_count == 0 and result_object.total_results > 0:
            if not analysis_results.evidence["pageHasNoTextSnippet"] and not analysis_results.evidence[
                "lowRelevanceTopResults"]:
                if (result_object.total_results <= 10
                        and analysis_results.evidence["business"]
                        and analysis_results.evidence["business"][0][0] == result_object.top_results[1][0]
                ):  # first search result is biz result
                    analysis_results.score = min(analysis_results.score, 4)
                    analysis_results.category = "New Business Site"
                    analysis_results.risk = "Likely Benign"
                    analysis_results.final_text += "There are very few results for this site, but the first result seems to be business-related. We feel that the business-related results that appeared are most meaningful. "
                elif (result_object.total_results <= 10 and not analysis_results.evidence["business"]):
                    analysis_results.category = "Uncommon Site"
                    analysis_results.risk = "Potentially Malicious"
                    analysis_results.final_text += "There were few results for this site, though none are associated with security tools. This site is very much unknown. It could be a threat (depending on how its activity appears). "
                    analysis_results.score = 5
                    analysis_results.print_top_results = True
                else:
                    analysis_results.category = "Common Site"
                    analysis_results.risk = "Benign"
                    analysis_results.final_text += "There were no results that indicated that this site has been analyzed in security tools, which strongly suggests that this site is uninteresting from a security perspective. "
                    analysis_results.score = 1
            elif (not analysis_results.evidence["pageHasNoTextSnippet"]
                  and analysis_results.evidence["business"]
            ):
                if result_object.total_results <= 10 and analysis_results.evidence["business"][0][0] == \
                        result_object.top_results[1][0]:  # first search result is biz result
                    analysis_results.score = min(analysis_results.score, 4)
                    analysis_results.category = "New Business Site"
                    analysis_results.risk = "Likely Benign"
                    if analysis_results.evidence["lowRelevanceTopResults"]:
                        analysis_results.final_text += "While there are some low-relevance top results (such as links to site traffic, when it was registered, etc...), w"
                    else:
                        "There are very few results for this site, but the first result seems to be business-related. W"
                    analysis_results.final_text += "e feel that the business-related results that appeared are most meaningful. "
                elif (analysis_results.evidence["lowRelevanceTopResults"]
                      and
                      (len(analysis_results.evidence["business"]) >= len(
                          analysis_results.evidence["lowRelevanceTopResults"])
                      )
                ):
                    analysis_results.score = min(analysis_results.score, 4)
                    analysis_results.category = "Business"
                    analysis_results.risk = "Likely Benign"
                    analysis_results.final_text += "While there are some low-relevance top results (such as links to site traffic, when it was registered, etc...), we feel that the business-related results that appeared are more meaningful. "
                else:
                    analysis_results.score = min(analysis_results.score, 4)
                    analysis_results.category = "Business"
                    analysis_results.risk = "Likely Benign"
                    analysis_results.final_text += "We have found business-related search results that lead us to believe that the site is more than likely benign. "
        else:
            if num_security_threat + num_vector + num_impact >= num_pup_threat:
                analysis_results.category = "Generic Malicious Site"
                analysis_results.risk = "Potentially Malicious"
            else:
                if (result_object.total_results > 0
                        and result_object.total_results < 2000
                        and not analysis_results.evidence["securityThreat"]
                        and not analysis_results.evidence["potentialVector"]
                        and not analysis_results.evidence["potentialImpact"]
                        and not analysis_results.evidence["pupThreat"]
                        and not analysis_results.evidence["lowRelevanceTopResults"]
                ):
                    if analysis_results.evidence["pageHasNoTextSnippet"]:
                        analysis_results.risk = "Potentially Malicious"
                        analysis_results.category = "Unknown Malicious Site"
                        analysis_results.final_text += "The first search result for this site is just a link to itself, which when combined with having a low number of overall results is correlated with an unknown malicious site. "
                    else:
                        analysis_results.category = "Uncommon Site"
                        analysis_results.risk = "Likely Benign"
                        analysis_results.final_text += "While there were few results for this site, none are associated with security tools. Overall, this suggests that this site is actually uninteresting from a security perspective. "
                        analysis_results.score = 4
                        analysis_results.print_top_results = True
                else:
                    if analysis_results.evidence["pupThreat"]:
                        analysis_results.category = "Potentially Unwanted Program (PUP)"
                    else:
                        analysis_results.category = "Generic Malicious Site"
                    analysis_results.risk = "Likely Malicious"
            if (analysis_results.evidence["securityThreat"]
                    or analysis_results.evidence["potentialVector"]
                    or analysis_results.evidence["potentialImpact"]
            ):
                if not analysis_results.evidence["pageHasNoTextSnippet"]:
                    if ((num_security_threat + num_pup_threat) < 5
                            and not analysis_results.evidence["potentialVector"]
                            and not analysis_results.evidence["potentialImpact"]
                    ):
                        if (not 10 in [ev[1] for ev in analysis_results.evidence["securityThreat"]]
                                and not 10 in [ev[1] for ev in analysis_results.evidence["potentialImpact"]]
                                and not 10 in [ev[1] for ev in analysis_results.evidence["potentialVector"]]
                                and result_object.total_results > 20):
                            analysis_results.category = "Generic Benign Site"
                            analysis_results.risk = "Likely Benign"
                            analysis_results.score = 4
                            analysis_results.final_text += "However, we've noticed that the matches that are security relevant are few in number, and most of the results point to this being a legitimate site. "
                            analysis_results.print_top_results = True
                if analysis_results.risk != "Likely Benign":
                    if analysis_results.evidence["potentialVector"]:
                        if 10 in [ev[1] for ev in analysis_results.evidence["potentialVector"]]:
                            analysis_results.category = "Phishing Site"
                            analysis_results.score = 10
                            analysis_results.risk = "Known Malicious"
                            analysis_results.final_text += "There is also evidence to support the fact that this site originally came from a document (such as through a phishing link):\n"
                            count = 1
                            for title in analysis_results.evidence["potentialVector"]:
                                analysis_results.final_text += ("\t"
                                                                + str(count)
                                                                + ". "
                                                                + title[0]
                                                                + "\n"
                                                                )
                        else:
                            analysis_results.final_text += "There are results that seemed to indicate that this site is associated with phishing, but based on the amount of search results, we believe that this is actually untrue. "
                    if analysis_results.evidence["potentialImpact"]:
                        analysis_results.category = "Impact-Causing Site"
                        analysis_results.score = 10
                        analysis_results.risk = "Known Malicious"
                        analysis_results.final_text += "There is also evidence to support the fact that this site causes a negative impact to your organization (such as downloading an executable file):\n"
                        count = 1
                        for title in analysis_results.evidence["potentialImpact"]:
                            analysis_results.final_text += ("\t"
                                                            + str(count)
                                                            + ". "
                                                            + title[0]
                                                            + "\n"
                                                            )
                    analysis_results.final_text += "The results that most strongly indicated that this was a security threat have the following title snippets:\n"
                    count = 1
                    for title in analysis_results.evidence["securityThreat"]:
                        if title[1] == 10:  # we had a known malicious result
                            analysis_results.final_text += ("\t"
                                                            + str(count)
                                                            + ". "
                                                            + title[0]
                                                            + " --> KNOWN MALICIOUS match\n"
                                                            )
                            analysis_results.risk = "Known Malicious"
                            analysis_results.score = 10
                        else:
                            analysis_results.final_text += ("\t"
                                                            + str(count)
                                                            + ". "
                                                            + title[0]
                                                            + "\n"
                                                            )
                        count += 1
                    if analysis_results.first_security_threat > 10:
                        analysis_results.final_text += (
                                "However, the first result that suggests this may be a threat is actually not even on the first page of search results (it's actually result #"
                                + str(analysis_results.first_security_threat)
                                + " of "
                                + str(result_object.total_results)
                                + "), meaning that it may not even be relevant. "
                        )
                        analysis_results.category = "Generic Benign Site"
                        analysis_results.risk = "Likely Benign"
                        analysis_results.score = 4
                    elif analysis_results.first_security_threat == 1:
                        if result_object.total_results == 1:
                            analysis_results.final_text += "The first result that suggests this may be a threat is actually the first and only search result, which is highly interesting."
                            analysis_results.score += 3
                        elif result_object.total_results <= 10:
                            analysis_results.final_text += "The first result that suggests this may be a threat is actually the first overall search result, and there are few search results. This makes the site more interesting from a security perspective."
                            analysis_results.score += 2
                        else:
                            analysis_results.final_text += "The first result that suggests this may be a threat is actually the first overall search result, though there are (relatively speaking) many search results. This is POTENTIALLY more interesting."
                            analysis_results.score += 1
            if analysis_results.evidence["pupThreat"]:
                analysis_results.final_text += "There are results that indicate that this site is associated with a Potentially Unwanted Program (PUP). A snippet of the titles for those results are:\n"
                count = 1
                for title in analysis_results.evidence["pupThreat"]:
                    analysis_results.final_text += ("\t"
                                                    + str(count)
                                                    + ". "
                                                    + title[0]
                                                    + "\n"
                                                    )
                    count += 1
    else:  # we believe it to be an attack hiding in SEO
        analysis_results.category = "Domain Spoofing Site"
        analysis_results.risk = "Likely Malicious"
    if analysis_results.evidence["business"]:
        if analysis_results.is_big_business:
            analysis_results.final_text += "However, some results suggest that this site is actually associated with a legitimate, large business. If true, this site may actually be trying to target a large brand in a domain typosquatting attack. A snippet of the titles for those results are:\n"
        else:
            analysis_results.final_text += "A snippet of the results that seem to suggest that this site is actually associated with a business (potentially a local business, which would most likely make the site uninteresting) are:\n"
        count = 1
        for title in analysis_results.evidence["business"]:
            analysis_results.final_text += ("\t"
                                            + str(count)
                                            + ". "
                                            + title[0]
                                            + "\n"
                                            )
            count += 1
    if input_type == "IP" and analysis_results.evidence["domainForIP"]:
        analysis_results.final_text += "Domains that may be related to this IP:\n"
        count = 1
        for title in analysis_results.evidence["domainForIP"]:
            if (result_object.total_results <= 25
                    and "Malicious" in analysis_results.category
                    and not 10 in [ev[1] for ev in analysis_results.evidence["securityThreat"]]
                    and not 10 in [ev[1] for ev in analysis_results.evidence["potentialImpact"]]
                    and not 10 in [ev[1] for ev in analysis_results.evidence["potentialVector"]]
            ):  # likely associated with one real domain
                if count == 1:
                    analysis_results.has_secondary_analysis = True
                    domain_analysis_results = main([title[0]], True)
                    return domain_analysis_results
                else:
                    continue  # only grab the top one for this
            analysis_results.final_text += ("\t"
                                            + str(count)
                                            + ". "
                                            + title[0]
                                            + "\n"
                                            )
            count += 1
    if analysis_results.print_top_results:
        analysis_results.final_text += "The top results for this site are:\n"
        count = 1
        for res in result_object.top_results:
            if count > 10:
                break
            title = str(result_object.top_results[res][0])  # str to handle special characters
            title = title.replace("http", "hxxp")
            title = title.replace("HTTP", "HXXP")
            link = result_object.top_results[res][1]
            link = link.replace("http", "hxxp")
            link = link.replace("HTTP", "HXXP")
            text_snippet = result_object.top_results[res][2]
            analysis_results.final_text += ("\t"
                                            + str(count)
                                            + ". "
                                            + title
                                            + " (link: "
                                            + link
                                            + ")\n\t\t"
                                            + text_snippet
                                            + "\n"
                                            )
            count += 1


def determine_if_likely_benign(result_object, analysis_results):
    """Determining if a site that looks benign is actually benign -- and if so, trying to determine what kind of benign
        site it is -- is really helpful in making better decisions about activity later on.
    """
    analysis_results.category = "Generic Benign Site"
    if (not analysis_results.evidence["securityThreat"]
            and not analysis_results.evidence["pupThreat"]
            and not analysis_results.evidence["potentialVector"]
            and not analysis_results.evidence["potentialImpact"]
    ):
        analysis_results.risk = "Benign"
    else:
        if not analysis_results.likely_seo_attack:
            analysis_results.risk = "Likely Benign"
        else:  # this hides well in benign results, but it's likely not benign
            analysis_results.category = "Domain Spoofing Site"
            analysis_results.risk = "Likely Malicious"
            analysis_results.score = 7
    if len(analysis_results.evidence["urlShortener"]) > 1:
        analysis_results.category = "URL Shortener"
        analysis_results.final_text += "More than one result suggests that this site is a URL shortener. While URL shorteners themselves aren't generally malicious, they can serve as an Attack Vector. "
    if analysis_results.evidence["business"]:
        analysis_results.category = "Business"
        if analysis_results.is_big_business:
            analysis_results.category = "Large Business"
            analysis_results.final_text += "Most results seem to suggest that this site is actually associated with a large, established business, which would most likely make the site uninteresting. A snippet of the titles for those results are:\n"
        else:
            analysis_results.final_text += "Most results seem to suggest that this site is actually associated with a business (potentially a local business), which would most likely make the site uninteresting. A snippet of the titles for those results are:\n"
        count = 1
        for title in analysis_results.evidence["business"]:
            analysis_results.final_text += ("\t"
                                            + str(count)
                                            + ". "
                                            + title[0]
                                            + "\n"
                                            )
            count += 1
    if analysis_results.evidence["securityThreat"]:
        analysis_results.final_text += "There are, however, results that seem to suggest that this site is a security threat. This can occur for a couple of reasons. First, the site's purpose may be hard to decipher (commonly occurs with ads, analytics, and other tracking technologies). Second, the site may appear often around some other interesting activity (this could mean that it is an Attack Vector). Finally, it could be malicious but not well-identified at this time. A snippet of the titles for those results are:\n"
        count = 1
        for title in analysis_results.evidence["securityThreat"]:
            analysis_results.final_text += ("\t"
                                            + str(count)
                                            + ". "
                                            + title[0]
                                            + "\n"
                                            )
            count += 1
    if analysis_results.evidence["pupThreat"]:
        analysis_results.final_text += "There are results that also indicate that this site is associated with a Potentially Unwanted Program (PUP). Those sites have the following title snippets:\n"
        count = 1
        for title in analysis_results.evidence["pupThreat"]:
            analysis_results.final_text += ("\t"
                                            + str(count)
                                            + ". "
                                            + title[0]
                                            + "\n"
                                            )
            count += 1
    analysis_results.final_text += "The title of the highest-ranked (which should mean the most relevant) search result is as follows:\n"
    analysis_results.final_text += ("\t"
                                    + str(result_object.top_results[1][0])
                                    )


def save_results_to_cache(result_object, site_term):
    """This occurs when we don't have cached results and want to save some. Generally, we should cache when we don't
        have any cached results.
    """
    if platform.system().lower() == "windows":
        search_cache_dir = str(pathlib.PurePath("C:\\TEMP\\search"))
        delimiter = "\\"
    else:
        search_cache_dir = str(pathlib.PurePath("/tmp/search"))
        delimiter = "/"
    pathlib.Path(search_cache_dir).mkdir(parents=True, exist_ok=True)  # make sure it exists
    filename = (search_cache_dir
                + delimiter
                + site_term
                + ".pkl"
                )
    filehandler = open(filename, "wb")
    # stringify dict to not throw errors
    result_object.top_results = str(result_object.top_results)
    pickle.dump(result_object, filehandler)


def retrieve_cached_results(site_term):
    """Retrieves results that are cached and returns them to object format.
    """
    if platform.system().lower() == "windows":
        search_cache_dir = str(pathlib.PurePath("C:\\TEMP\\search"))
        delimiter = "\\"
    else:
        search_cache_dir = str(pathlib.PurePath("/tmp/search"))
        delimiter = "/"
    pathlib.Path(search_cache_dir).mkdir(parents=True, exist_ok=True)  # make sure it exists
    filename = (search_cache_dir
                + delimiter
                + site_term
                + ".pkl"
                )
    try:
        cache_file = open(filename, "rb")
        result_object = pickle.load(cache_file)
    except pickle.UnpicklingError as e:
        logger.info("Error unpickling: " + str(e))
        return None
    except:
        return None
    # "rehydrate" dict from string representation
    try:
        result_object.top_results = ast.literal_eval(result_object.top_results)
        logger.info("From cached search entry, top results: "
                     + str(result_object.top_results)
                     )
    except:
        logger.info("Failed to rehydrate dictionary for "
                     + result_object.search_term
                     + ". Results will be wrong for this entry."
                     )
        result_object.top_results = dict()
    return result_object


def do_search(term, input_type, num_results=10, use_custom_engine=True):
    return search_results.search(term, input_type, num_results)


def collect_destination_verdicts(unknown_destinations):
    search_results = dict()

    for unknown in unknown_destinations:
        colpos = unknown.rfind(":")
        if colpos == -1:
            destination_term = unknown
        else:
            destination_term = unknown[:unknown.rfind(":")]
        try:
            if ipaddress.ip_address(destination_term):
                input_type = "IP"
            else:
                input_type = "domain"
        except:
            input_type = "domain"
        result_object = retrieve_cached_results(destination_term)
        if result_object is not None:
            logger.info("Found cached result for "
                         + destination_term
                         + ":"
                         )
            analyzed_results = analyze_search_results(result_object, input_type)
        else:  # either not cached, or cache entry had nothing useful (maybe?)
            logger.info("Nothing useful in cache, so about to do actual search for "
                         + input_type
                         + " "
                         + destination_term
                         )
            result_object = do_search(destination_term, input_type)
            if result_object is None:
                logger.info("Search still failed for "
                             + input_type
                             + " "
                             + destination_term
                             )
                analyzed_results = None
            else:
                analyzed_results = analyze_search_results(result_object, input_type)
                save_results_to_cache(result_object, destination_term)
        search_results[destination_term] = analyzed_results
    return search_results


def main(args, was_secondary_analysis=False):
    ip_addr = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\.|)$")
    google_user_content_ip = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.bc\.googleusercontent\.com$")
    input_type = "domain"  # by default, assume domain
    try:
        site_term = args[0]
    except:
        pass
    load_results_from_cache = False
    if len(args) > 1:
        if args[1] == "loadCache":
            load_results_from_cache = True
        else:
            num_results = args[1]
        if re.findall(ip_addr, site_term):
            input_type = "IP"
        elif re.findall(google_user_content_ip, site_term):
            input_type = "IP"
            tmp = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", site_term)[0]
            site_term = ".".join(reversed(tmp.split(".")))
            logger.info("Treating Google User Content entry as an IP.")
        if not load_results_from_cache:
            result_object = do_search(site_term, input_type, num_results)
        else:
            result_object = retrieve_cached_results(site_term)
    elif len(args) == 1:
        if re.findall(ip_addr, site_term):
            input_type = "IP"
        elif re.findall(google_user_content_ip, site_term):
            input_type = "IP"
            tmp = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", site_term)[0]
            site_term = ".".join(reversed(tmp.split(".")))
            logger.info("Treating Google User Content entry as an IP.")
        if not load_results_from_cache:
            result_object = do_search(site_term, input_type)
        else:
            result_object = retrieve_cached_results(site_term)
    else:
        return

    if len(result_object.top_results) < 1 and result_object.total_results > 0:
        return
    final_data = analyze_search_results(result_object, input_type, was_secondary_analysis)
    if not load_results_from_cache:
        save_results_to_cache(result_object, site_term)
    return final_data


if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
