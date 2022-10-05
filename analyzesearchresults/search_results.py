"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import json
import logging
import sys

from bs4 import BeautifulSoup
from requests import get

from analyzesearchresults import search_result

logger = logging.getLogger("SearchResults")

"""Some minor portion of this is an extension of https://github.com/Nv7-GitHub/googlesearch. Note that this has been
   phased out in favor of a custom search engine registered to us.
"""


def search(term, input_type, num_results=10, lang="en", use_custom_engine=True):
    """Search the Internet using Google for all results for the search term. Collect the top 10 results for closer
        analysis in later steps.
    """
    usr_agent = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/98.0.4758.102 Safari/537.36"}

    # TODO: Keep user agent updated

    def fetch_results(search_term, input_type, number_results, language_code, use_custom_engine):
        """Actually fetch the results from Google.
        """
        question = ""

        if input_type == "IP":
            """When we have an IP address to be searched, adding + "domain" helps us to focus in on results that tell
                us if this is actually known to be involved with domains. If there are many results, it's likely that
                this IP is part of some CDN's infrastructure and could be anything. If there are few results, it's
                likely that this IP is associated with one site. We can then look at the results' titles to see if those
                sites are interesting.
            """
            question = '"' + search_term + '"+AND+"domain"'  # adding "domain" helps us to receive better, more relevant answers
        elif input_type == "domain":
            question = '"' + search_term + '"'
        else:
            logger.info("Unknown input type. Quitting.")
            sys.exit()
        if use_custom_engine:
            """We now have a custom search engine that allows us to query Google automatically without breaking their
                TOS. Use this by default.
            """
            key = ""  # this is our API key. It should be kept private
            cx = ""  # this is our custom search ID.
            google_url = ('https://www.googleapis.com/customsearch/v1?key='
                          + key
                          + '&cx='
                          + cx
                          + '&q={}&hl={}'.format(question
                                                 , language_code
                                                 )
                          )
        else:
            google_url = 'https://www.google.com/search?q={}&num={}&hl={}'.format(question
                                                                                  , number_results + 1,
                                                                                  language_code
                                                                                  )
        try:
            if use_custom_engine:
                response = get(google_url)
            else:
                response = get(google_url, headers=usr_agent)  # otherwise our UA would be something to do with Python
            response.raise_for_status()
            return response.text
        except:
            logger.info("Something failed while trying to fetch search results. Returning None.")
            return None

    def parse_json_results(json_data, term):
        """Parse the actual results of the returned data.
        """
        result_object = search_result.SearchResult(term)
        try:
            result_object.total_results = int(json_data["searchInformation"]["totalResults"])
        except:
            pass  # some sort of error happened here
        # there are no ads in the Custom Search Engine results...
        # try:
        #    if result_object.total_results == -1:
        #        adsSection = soup.find(("div"), attrs={"data-text-ad":"1"})
        #        result_object.ads_text = adsSection.get_text()
        # except:
        #    pass # no ads found
        # try:
        #    if result_object.total_results == -1: #we have quoted results
        #        resultsSection = soup.find(("div"), attrs={"logId": "result-stats"})
        #        resultsEnd = resultsSection.get_text().find(" result")
        #        resultsCount = resultsSection.get_text()[:resultsEnd].split(" ")[-1]
        #        result_object.total_results = int(resultsCount.replace(",", ""))
        #        #print("Result count:", result_object.total_results)
        # except:
        #    pass #print("No results found")
        if result_object.total_results == 0:  # have to do this in case we have only unquoted results
            return result_object
        # we now know we have results, so collect their information!
        count = 1
        for result in json_data["items"]:
            try:
                link = result["link"]
            except:
                link = ""
            try:
                title = result["title"]
            except:
                title = ""
            try:
                snippet = str(result["snippet"])
            except:
                snippet = ""
            result_object.top_results[count] = (title, link, snippet)
            count += 1
        """ LDA Topic modeling occurs here. Currently turned OFF because it is
            expensive (~5 seconds to run per site) and on average the topics
            weren't terribly helpful in guiding my decision-making. Can revisit
            in the future.
        """
        # if len(result_object.top_results) > 0:
        #    result_object.getTopicsFromSearch()
        return result_object

    def parse_results(raw_html, term):
        """Parse the actual results of the returned data. This should only fail if Google changes something in the way
           they return results. It has stayed sane for months (so far).
        """
        soup = BeautifulSoup(raw_html, "html.parser")
        result_object = search_result.SearchResult(term)
        try:
            quoted_results_section = soup.find(("div"), attrs={"aria-level": "2", "role": "heading"})
            quoted_results_end = quoted_results_section.get_text().find(" result")
            quoted_results_exist = quoted_results_section.get_text()[:quoted_results_end].split(" ")[-1]
            if quoted_results_exist == "No":
                result_object.total_results = 0
        except:
            pass  # actually no results found, though it found unquoted results
        try:
            if result_object.total_results == -1:
                adsSection = soup.find(("div"), attrs={"data-text-ad": "1"})
                result_object.ads_text = adsSection.get_text()
        except:
            pass  # no ads found
        try:
            if result_object.total_results == -1:  # we have quoted results
                resultsSection = soup.find(("div"), attrs={"logId": "result-stats"})
                resultsEnd = resultsSection.get_text().find(" result")
                resultsCount = resultsSection.get_text()[:resultsEnd].split(" ")[-1]
                result_object.total_results = int(resultsCount.replace(",", ""))
                # print("Result count:", result_object.total_results)
        except:
            pass  # print("No results found")
        if result_object.total_results == 0:  # have to do this in case we have only unquoted results
            return result_object
        result_block = soup.find_all("div", attrs={"class": "g"})
        count = 1
        for result in result_block:
            link = result.find("a", href=True)
            text_snippet = ""
            try:
                text_snippet = result.find("div", attrs={"style": "-webkit-line-clamp:2"}).get_text()
                "".join(text_snippet)
                if text_snippet == "":
                    text_snippet = result.find("span", attrs={"class": None}).get_text()
                    "".join(text_snippet)
            except:
                pass
            try:
                title = result.find("h3").contents[0]
                result_object.top_results[count] = (title, link["href"], str(text_snippet))
                count += 1
            except:
                continue  # print("Failed for result", link)
        """ LDA Topic modeling occurs here. Currently turned OFF because it is
            expensive (~5 seconds to run per site) and on average the topics
            weren't terribly helpful in guiding my decision-making. Can revisit
            in the future.
        """
        # if len(result_object.top_results) > 0:
        #    result_object.getTopicsFromSearch()
        return result_object

    results = fetch_results(term, input_type, num_results, lang, use_custom_engine)
    if results is None:
        return None
    if use_custom_engine:  # Google's custom search engine returns JSON
        try:
            result_data = json.loads(results)
        except:
            logger.info("Loading JSON from custom search engine results failed.")
            return None
        return parse_json_results(result_data, term)
    return parse_results(html, term)  # otherwise we'll have HTML data to parse
