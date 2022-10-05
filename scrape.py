"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import argparse
import json
import re
import sys
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

import twitter_setup


def load_twitter_results(filename):
    with open(filename, "r") as saved_results:
        results = json.load(saved_results)
    return results


def collect_twitter(**kwargs):
    start_time = kwargs["time"]
    results_data_dict = kwargs["results_data"]
    # fresh = kwargs["fresh"]

    # print("In collect twitter, time is", now)

    # if fresh:
    search_url = "https://api.twitter.com/2/tweets/search/recent"
    # Optional params: start_time,end_time,since_id,until_id,max_results,next_token,
    # expansions,tweet.fields,media.fields,poll.fields,place.fields,user.fields
    # query_params = {"query": "(from:twitterdev -is:retweet) OR #twitterdev","tweet.fields": "author_id"}
    # query_params = {"query":"(phishing -is:retweet)", "start_time":start_time, "max_results":"10", "tweet.fields":"entities","expansions":"author_id", "user.fields":"description"}
    query_params = {"query": "(phishing -is:retweet)", "start_time": start_time, "tweet.fields": "context_annotations",
                    "expansions": "author_id", "user.fields": "description"}
    results = twitter_setup.setup(search_url, query_params)

    with open("tmp_twitter.txt", "w") as f:
        f.write(results)
    print("results written to tmp_twitter.txt")

    results = load_twitter_results("tmp_twitter.txt")
    # with open("tmp_twitter.txt", "r") as saved_results:
    #    results = json.load(saved_results)
    if results["meta"]["result_count"] == 0:
        return
    print(str(len(results["data"])), "results loaded from tmp_twitter.txt")
    print("Parsing results")
    if "twitter" in results_data_dict.keys():
        results_data_dict["twitter"] += [parse_twitter_results(results)]
    else:
        results_data_dict["twitter"] = [parse_twitter_results(results)]
    if len(results_data_dict["twitter"]) == 0:
        print("No Twitter results contained valid links")
    # results_data.put(parse_twitter_results(results))


def lookup_username_by_author_id(author_id, username_mapping):
    username = "@"

    if author_id not in username_mapping.keys():
        users_url = "https://api.twitter.com/2/users"
        query_params = {"ids": author_id, "user.fields": "username"}
        result = json.loads(twitter_setup.setup(users_url, query_params))
        # print("Result:", result)
        return username + result["data"][0]["username"]
    return username_mapping[author_id]


def rebuild_link(link):
    link = re.sub(r"\[\.\]", ".", link, flags=re.IGNORECASE)
    link = re.sub(r"^\/{1,2}", "https://", link, flags=re.IGNORECASE)
    link = re.sub(r"^hxxps", "https", link, flags=re.IGNORECASE)
    link = re.sub(r"^hxxp", "http", link, flags=re.IGNORECASE)
    if not link.startswith("http"):
        link = "https://" + link

    destination = urlparse(link).netloc
    # print("Destination:", destination)
    if len(destination) == 0:
        print("Something went wrong parsing destination from suspected link " + link + " Skipping.")
        return None
    return link


def parse_twitter_results(results):
    # TODO: This could potentially handle ALL results, but let's start with Twitter
    temporary_username_mapping = dict()
    twitter_results = dict()
    ignored_users = []

    for result in results["data"]:
        confidence = 0
        tweet = result["text"]
        author_id = result["author_id"]
        twitter_handle = lookup_username_by_author_id(author_id, temporary_username_mapping)
        temporary_username_mapping[author_id] = twitter_handle
        # try:
        #    url_entities = result["entities"]["urls"]
        # except:
        #    print("Found no links in tweet. Skipping this tweet:", tweet)
        #    continue
        # for url_data in url_entities:
        #    print("URL info:")
        #    print(url_data.items())
        if twitter_handle[1:] in ignored_users:
            print("Ignoring tweet from user", twitter_handle)
            continue
        link_data = re.search(
            "((((h|H)(tt|xx|TT|Tt|tT|XX|Xx|xX)(p|P)|(h|H)(tt|xx|TT|Tt|tT|XX|Xx|xX)(p|P)(s|S)):\/\/)|\/|s:\/\/)?(([a-zA-Z0-9\-]+(\[\.\]|\.))+((\S[a-zA-Z]{1,9})|[0-9]))+((\/\S+)?)+(\/|\.|\S*)",
            tweet)
        if link_data:
            # print("Link data:", link_data)
            link = tweet[link_data.start():link_data.end()]
        else:
            # print("Error: no link seen in", tweet)
            continue
        # print("Link:", link)
        if link:
            link_twitter_data = re.search("^(https://t\.co)", link)
        else:
            continue
        if link_twitter_data:
            # print(link, "is a Twitter link, which we don't care about. Skipping the following tweet:", tweet)
            continue
        uncertain = re.search(r"(((P|p)ossibl(e|y))|((L|l)ikely))", tweet)
        # print("Raw link:", link)
        link = rebuild_link(link)
        if link is None:
            continue  # it wasn't actually a link
        if uncertain:
            # print("Found POSSIBLE candidate phishing link", link, "in", twitter_handle+""s tweet:", tweet)
            confidence = 50
        else:
            # print("Found candidate phishing link", link, "in", twitter_handle+"'s tweet:", tweet)
            confidence = 75
        if link.endswith("[.]zip") or "#opendir" in tweet:
            print("Skipping #opendir tweet with link", link)
            continue
        if twitter_handle in twitter_results.keys():
            twitter_results[twitter_handle] += [
                {"category": "phishing", "confidence": confidence, "tweet": tweet, "links": [link]}]
        else:
            twitter_results[twitter_handle] = [
                {"category": "phishing", "confidence": confidence, "tweet": tweet, "links": [link]}]
        # print("Uncertainty:", uncertain)
    return twitter_results


def get_latest(url, topic, source):
    response = requests.get(url)
    with open("results.html", "w") as f:
        f.write(response.text)
    return response.text


def return_source_links(href):
    source = "twitter.com"
    return href and re.compile(source).search(href)


def parse_results(raw_html, topic, source):  # raw_html, term):
    # print("Response data:", response.text)

    soup = BeautifulSoup(raw_html, "html.parser")
    # print("Raw data:", soup.prettify())

    topic_results = soup.find_all(href=return_source_links, string=re.compile(topic))
    json_output_file = open("results_formatted.json", "w")
    json_output_file.write('{\n\t"destinations":\n\t\t[')
    failed_or_skipped_file = open("failed_or_skipped.txt", "w")
    i = 0

    for result in topic_results:
        link_data = re.search(
            "((((h|H)(tt|xx|TT|Tt|tT|XX|Xx|xX)(p|P)|(h|H)(tt|xx|TT|Tt|tT|XX|Xx|xX)(p|P)(s|S)):\/\/)|\/|s:\/\/)?(([a-zA-Z0-9\-]+(\[\.\]|\.))+((\S[a-zA-Z]{1,9})|[0-9]))+((\/\S+)?)+(\/|\.|\S*)",
            result.string)
        if link_data:
            # print("Link data:", link_data)
            link = result.string[link_data.start():link_data.end()]
        else:
            continue
        # print("Link:", link)
        if link:
            link_twitter_data = re.search("^(https://t\.co)", link)
        else:
            continue
        if link_twitter_data:
            continue
        data = {}
        twitter_handle_raw = re.search(r"\/twitter\.com\/([^\/]*)\/", result.get("href")).group()
        if twitter_handle_raw:
            twitter_handle = "@" + twitter_handle_raw[13:-1]
        else:
            print("Something went wrong extracting Twitter handle. Skipping this entry.")
            continue
        tweet = result.string
        # print("Tweet:", result.get("href"))
        # print("\tContent:", result.string)
        # print("Non-Twitter link:", link)
        uncertain = re.search(r"(((P|p)ossibl(e|y))|((L|l)ikely))", tweet)
        # print("Uncertainty:", uncertain)
        if uncertain:
            # print("Tweet seems uncertain about this being a phish. Skipping. Here is the tweet:", tweet)
            failed_or_skipped_file.write(
                "Tweet seems uncertain about this being a phish. Skipping. Here is the tweet: " + tweet + "\n\n")
            continue
        destination = urlparse(link).netloc
        destination = destination.replace("[", "")
        destination = destination.replace("]", "")
        # print("Destination:", destination)
        if len(destination) == 0:
            failed_or_skipped_file.write(
                "Something went wrong parsing destination from tweet, so we're skipping. Tweet is " + tweet + "\n\n")
            continue
        if ":" in destination:
            print("Destination", destination, "already has a port. Using it.")
            data["destinationName"] = destination
        else:  # default to 443 if no port
            data["destinationName"] = destination + ":443"
        data["title"] = "Known " + topic.capitalize() + " Site"
        data[
            "description"] = "This Destination is known to be a " + topic + " site. It was discovered by Twitter user " + twitter_handle
        data["relevance"] = "knownBad"
        data["destinationTags"]: ""
        data["platformHintTags"]: ""
        data["associatedAppOrServiceTags"]: ""
        data["impactsTags"]: ""
        data["activityPurposeTags"]: ""
        data["attackVectorTags"]: ""
        data["threatTags"]: ["Phishing"]
        data["securityTags"]: ""
        if i != 0:
            json_output_file.write("\n\t\t,")
        i += 1
        json_output_file.write(json.dumps(data))
    json_output_file.write("\n\t]\n}")
    json_output_file.close()
    failed_or_skipped_file.close()
    print("Failures/skips written to failed_or_skipped.txt")
    print("Prepped results written to results_formatted.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    inputGroup = parser.add_argument_group("inputData", "arguments available for providing information about the input")
    inputGroup.add_argument("-i", "--inputfile", help="a valid input HTML file", type=str)
    inputGroup.add_argument("--fresh", help="request a fresh lookup", action="store_true")
    inputGroup.add_argument("--topic", help="topic to look up", type=str)
    inputGroup.add_argument("--source", help="source to look up", type=str)

    args = parser.parse_args()
    if args.inputfile and args.fresh:
        print("Can only provide an input file or request a fresh pull, not both. Aborting!")
        sys.exit(1)

    url = "https://www.threatable.io/"
    # topic="phishing"
    # source="twitter.com"
    if args.fresh:
        response_data = get_latest(url, args.topic, args.source)
    else:
        try:
            with open(args.inputfile, "r") as f:
                response_data = f.read()
        except:
            print("Failed to open", args.inputfile + ". Aborting!")
            sys.exit(1)
    parse_results(response_data, args.topic, args.source)
