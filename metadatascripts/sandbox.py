"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import io
import ipaddress
import json
import re
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests

import utilities


def call_sandbox(mode, servername, destination, upload_choice=True, user_response_required=True):
    try:
        if mode == "manual" or mode == "automated":
            endpoint_url = servername + "/analyze"
            request_headers = {"content-type": "application/json"
                               }
            data = dict()
            data["mode"] = mode
            data["destination"] = destination
            if upload_choice:
                data["upload"] = True
            request = requests.Request("POST", endpoint_url, data=json.dumps(data), headers=request_headers)
            prepped = request.prepare()
            if user_response_required:
                print("Ready to send following content to", prepped.url + ":", prepped.body)
                # TODO: When this is a manual send, we should get the user's attention somehow before proceeding.
                input("Press enter to send this information:")
            s = requests.Session()
            result = s.send(prepped)
            return result
        else:
            print("Unrecognized mode", mode, "for sandbox. Aborting!")
            sys.exit(1)
    except:
        print("Something failed while trying to start", mode, "sandbox.")
        return None


def upload_sample(api_key, servername, sample_name, sample_data):
    if api_key is None:
        print("Missing an API key. Please provide.")
        sys.exit(1)
    try:
        endpoint_url = servername + "/upload"
        request_headers = {"apikey": api_key
                           }
        data = dict()
        data["type"] = "pcap"
        data["filename"] = sample_name
        files = {"file": (sample_name, sample_data, "application/octet-stream")}
        req = requests.Request("POST", endpoint_url, headers=request_headers, files=files, data=data)
        prepped = req.prepare()
        print("Preparing to upload", sample_name)
        # print("Request data:", prepped.method, prepped.url, prepped.headers.items(), prepped.body)
        # input("Press enter to send this information:")
        s = requests.Session()
        result = s.send(prepped)
        # result = requests.post(endpoint_url, headers = request_headers, files = files, data = request_data)
        result_json = json.loads(result.text)
        return result_json
    except:
        print("Something failed while trying to prepare sample upload. Activity cannot be analyzed.")
        return None
        # sys.exit(1)


def handle_sandbox_result(result_data, api_key, servername):
    response = None
    try:
        if result_data.headers["Content-Disposition"].startswith("attachment;"):
            try:
                name_raw = re.search("filename=[0-9]{10}_[0-9]{1,9}_[0-9a-zA-Z:\&\.%\-\/#_\-\?\*\~\+\!\=\;\@]+\.zip",
                                     result_data.headers["Content-Disposition"])
                name = name_raw.group(0).split("=")[1]
            except:
                print("Something is wrong with incoming data from", str(result_data.headers))
                return response

            if result_data.headers["Content-Type"] == "application/octet-stream":
                sample_data = None
                sample_name = None
                zip_bytes = io.BytesIO(result_data.content)
                zipfile_ob = zipfile.ZipFile(zip_bytes)
                # print("ZIP contents:", zipfile_ob.namelist())
                Path("Sample_Data").mkdir(parents=True, exist_ok=True)
                zipfile_ob.extractall("Sample_Data")  # save them in the Sample_Data directory
                print("Saved contents into Sample_Data directory")
                for item_name in zipfile_ob.namelist():
                    if item_name.endswith(".pcap"):
                        sample_name = Path(item_name).stem + ".pcap"
                        # print("Collecting PCAP", sample_name)
                        with open(Path("Sample_Data").joinpath(item_name), "rb") as fin:
                            sample_data = fin.read()
                        break  # we don't need to do any more in here.
                if sample_data and sample_name:
                    response = upload_sample(api_key, servername, sample_name, sample_data)
                if response is None:
                    print("Some unknown error occurred while uploading file. Analysis will not continue.")
                    return response
                elif response["error"]:
                    print("Error occurred:", response["body"])
                    response = None
                else:
                    print("File information:")
                    print("\tFilename:", response["fileName"])
                    print("\tPublic UUID:", response["uuid"])
                    print("\tPublic Link:", response["link"])
                    print("\tPrivate sample ID:", response["sampleId"])
            else:
                print("Something went wrong handling sandbox result.")
        else:
            print("Something went wrong handling sandbox result.")
    except:
        print("Incoming data from sandbox seems to be malformed. Result data:", str(result_data))
    return response


def parse_mitm_file(mitm_filename):
    """
        Looks through the pretty-printed MITM file and for each destination, collects the HTTP method, request headers, response headers, and body.
    """

    http_requests = []  # store each entry as a dict within this list
    with open(mitm_filename, "r") as http_data:
        request_dict = dict()
        get_destination = False
        get_method_and_uri_data = False
        get_request_headers = False
        get_response_headers = False
        get_body = False

        for line in http_data:
            line_data = line.split()
            if len(line_data) == 0 or line.startswith("===="):
                if get_body:
                    # we just hit the end of body collection, so clean up and push to list
                    get_body = False
                    # print("Saving dictionary for request", str(len(http_requests)+1), "to destination", request_dict["destination"])
                    http_requests += [request_dict]
                get_destination = True  # get ready to collect the next destination
                continue
            else:
                # print("Line data:", line_data)
                if line.startswith("Destination:"):
                    if get_destination:
                        request_dict = dict()  # reset it, since we're just capturing it temporarily before storing into list
                        request_dict["destination"] = line_data[1]
                        # print("Saved destination", request_dict["destination"])
                        get_destination = False
                        get_method_and_uri_data = True
                        continue
                else:
                    if get_method_and_uri_data:
                        request_dict["method"] = line_data[0]
                        request_dict["uri"] = line_data[1]
                        get_method_and_uri_data = False  # done collecting
                        get_request_headers = True  # next to collect
                        continue
                    elif get_request_headers:
                        if line.startswith("----") and len(line_data) == 4:
                            if "request" in line_data:
                                # it's the request delimiter line, so set up collection
                                request_dict["request_headers"] = dict()
                            elif "response" in line_data:
                                # it's the response delimiter line, so clean up and set up that collection
                                get_request_headers = False
                                get_response_headers = True
                                request_dict["response_headers"] = dict()
                            else:
                                print("Unhandled line type", line)
                            continue
                        else:
                            request_dict["request_headers"][line_data[0]] = " ".join(line_data[2:])  # skip the colon
                    elif get_response_headers:
                        if line.startswith("----") and len(line_data) == 7:
                            # we hit the body line, so clean up and set up that collection
                            get_response_headers = False
                            get_body = True
                        else:
                            request_dict["response_headers"][line_data[0]] = " ".join(line_data[2:])  # skip the colon
                    elif get_body:
                        request_dict["body"] = line  # consume whole line
        # print("Saving dictionary for LAST request", str(len(http_requests)+1), "to destination", request_dict["destination"])
        http_requests += [request_dict]
        return http_requests


def collect_interesting(http_requests):
    """
        Takes the dict of HTTP requests parsed from a MITM file and collects (by destination field) any results that have interesting activity (as defined in this function).
    """

    keywords_regex = re.compile("")
    interesting_results = dict()
    interesting_request_headers = ["ORIGIN", "HOST", "REFERER", "CONTENT-TYPE"]
    interesting_response_headers = ["ACCESS-CONTROL-ALLOW-ORIGIN"]

    for request in http_requests:
        matched = re.search(keywords_regex, request["body"])
        if matched:
            # print(request["destination"], "has a keyword in its body! Details:")
            # print("\tBody:", request["body"])
            # print("\tRequest Type:", request["method"], "request to", request["uri"])
            # print("\tInteresting REQUEST headers:")
            request_general = dict()
            interesting_request_headers_found = dict()
            interesting_response_headers_found = dict()
            request_general["uri"] = request["uri"]
            request_general["method"] = request["method"]
            request_general["body"] = request["body"]
            request_general[
                "destination_resolved"] = None  # we haven't yet resolved anything, so hold onto this to populate later
            for header_name in request["request_headers"].keys():
                if header_name.upper() in interesting_request_headers:
                    # print("\t\t", header_name, request["request_headers"][header_name])
                    interesting_request_headers_found[header_name] = request["request_headers"][header_name]
            # print("\tInteresting RESPONSE headers:")
            for header_name in request["response_headers"].keys():
                if header_name.upper() in interesting_response_headers:
                    # print("\t\t", header_name, request["response_headers"][header_name])
                    interesting_response_headers_found[header_name] = request["response_headers"][header_name]
            if request["destination"] not in interesting_results.keys():
                # {"method": request["method"], "uri": request["uri"], }
                interesting_results[request["destination"]] = [request_general, interesting_request_headers_found,
                                                               interesting_response_headers_found]
            else:
                interesting_results[request["destination"]] += [request_general, interesting_request_headers_found,
                                                                interesting_response_headers_found]
    return interesting_results


def analyze_http_behavior(mitm_filename):
    """
        Takes a MITM file, parses it, and iterates through the list of dictionaries of HTTP requests collected from it
        to look for which bod(y|ies) contain(s) keywords that we put into any forms while live (username/email will
        always be "", password will always be "", TBD on other inputs). For those that contain that information, do a
        DNS lookup on any HTTP Request "Origin", "Host", or "Referer" fields' values (or the Response's
        "Access-Control-Allow-Origin" field's value) and see if any of the returned IPs match that of the "Destination"
        field. If so, report back that Destination's information (specifically the name, IP, HTTP method, HTTP URI,
        Referer, Request "Content-Type" field's value).

        Possibly keep track of other stuff in a future improved version.

    """

    http_requests = parse_mitm_file(mitm_filename)
    # print("Ready to look for keywords in", str(len(http_requests)), "HTTP requests") #. First one looks as follows:", http_requests[0].items())
    interesting_results = collect_interesting(http_requests)
    if len(interesting_results) == 0:
        print("Nothing interesting found in this MITM file.")
        return

    headers_with_candidate_domains = ["ORIGIN", "HOST", "REFERER", "ACCESS-CONTROL-ALLOW-ORIGIN"]
    likely_actual_domain_headers = ["ORIGIN", "HOST", "ACCESS-CONTROL-ALLOW-ORIGIN"]
    known_mappings = dict()

    for destination in interesting_results.keys():
        try:
            if ipaddress.ip_address(destination):
                for request in reversed(interesting_results[destination]):
                    # print("Request", request)
                    if "destination_resolved" not in request.keys():  # we're dealing with a request or response headers dict
                        for key in request.keys():
                            if key.upper() in headers_with_candidate_domains:
                                candidate_domain = urlparse(request[key]).netloc
                                # print("Checking to see if", candidate_domain, "resolves to", destination)
                                if destination in known_mappings.keys():
                                    if known_mappings[destination] is None:
                                        print("We know there's no match for", destination)
                                    # else:
                                    #    request["destination_resolved"] = candidate_domain
                                    continue  # skip the remaining logic
                                if utilities.lookup_ips_for_name(candidate_domain, destination):
                                    # print(candidate_domain, "does resolve to", destination+". Updating our records!")
                                    # print("Before, length of dict is", str(len(request)), "and dict is", request.items())
                                    # request["destination_resolved"] = candidate_domain
                                    # print("After, length of dict is", str(len(request)), "and dict is", request.items())
                                    known_mappings[
                                        destination] = candidate_domain  # save locally to not re-analyze same thing over and over
                                elif key.upper() in likely_actual_domain_headers:
                                    known_mappings[destination] = candidate_domain
                                else:
                                    print("Either", candidate_domain,
                                          "no longer resolves to an IP address, or it does not match the IP (" + destination + ") we know about.")
                                    known_mappings[destination] = None  # it failed, and it is expected to keep failing
                    else:  # we're in the general list
                        # print("Currently looking at", request, "and checking to see if", destination, "is in", known_mappings.keys())
                        if destination in known_mappings.keys():
                            # print("Updating request knowledge from", request["destination_resolved"], "to"),
                            request["destination_resolved"] = known_mappings[destination]
                            # print(request["destination_resolved"])

        except ValueError:
            print(destination, "may already be a name...should populate resolved field")
    return interesting_results
