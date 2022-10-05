"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import ast
import copy
import json
import os
import pprint
import re
import sys
import threading
import time

from flask import Flask
from flask import Response
from flask import request

import utilities
from interactivity import slack
from metadatascripts import sandbox, modify_metadata, authentication
from testing import testing

# create the Flask app
networkSage_slackbot = Flask(__name__)

# Identify the dict of privileged users by Slack user_id
privileged_users = {}


def interact_with_sandbox(mode, candidate_link):
    sample_info = dict()
    sandbox_servername = ""
    results = dict()
    if candidate_link[0] == "<" and candidate_link[-1] == ">":
        candidate_link = candidate_link[1:-1]

    sandbox_analysis_results = sandbox.call_sandbox(mode, sandbox_servername, candidate_link, True,
                                                    False)  # try to upload, don't require user intervention
    if sandbox_analysis_results is None:
        msg = "Something failed while trying to start " + mode + " sandbox."
        results["text"] = msg
    else:
        api_key = None
        if mode == "automated":
            api_key = os.environ.get("AUTOMATEDSAGE_API_TOKEN")
            if api_key is None:
                print("No API key specified. Please export AUTOMATEDSAGE_API_TOKEN.")
                sys.exit(1)
        elif mode == "manual":
            api_key = os.environ.get("MANUALSAGE_API_TOKEN")
            if api_key is None:
                print("No API key specified. Please export MANUALSAGE_API_TOKEN.")
                sys.exit(1)
        else:
            print("Unrecognized mode. Quitting.")
            sys.exit(1)
        sample_info = sandbox.handle_sandbox_result(sandbox_analysis_results, api_key,
                                                    sandbox_servername)  # upload actually happens here
        if sample_info is None:
            msg = "Some error occurred while uploading file. Analysis will not continue."
            results["text"] = msg
    if len(sample_info) > 0:
        link = utilities.generate_sample_link_from_uuid(sample_info["uuid"])
        if link is None:
            return False  # something went wrong
        msg = (mode.capitalize()
               + " sample creation successful. Beginning to automatically collect additional evidence. To view the automated sample, click <"
               + link
               + "|here>: "
               )
    else:
        msg = "Error creating sample. Quitting."
    if mode == "manual":
        """ For results that have a successful manual sandbox run, we should
            analyze the sandbox MITM file to understand anything about the destinations, including which may be a credential stealer, attack vectors, etc...
        """
        path_info = ""

        analyzed_manual_sandbox_results = sandbox.analyze_http_behavior(
            path_info + sample_info["fileName"][:-4] + "mitm")
        final_data = dict()
        final_data["sample_info"] = sample_info
        final_data["http_results"] = analyzed_manual_sandbox_results
        final_data["data_location"] = path_info + sample_info["fileName"]
        return final_data
        # print("Analysis from sandbox HTTP data shows the following interesting behavior:", analyzed_sandbox_results.items())
    else:  # automated sandbox analysis
        path_info = ""
        analyzed_manual_sandbox_results = None


def interact_with_metadata(mode, destination, userid, trigger_id, response_url):
    """Allows user to interact with NetworkSage to add new Destinations, modify existing Destinations, or perform a
        Destination lookup. For privileged functionality (adding or modifying Destination metadata), the Slack userid is
        checked against the list of privileged userids. Only those with privileged IDs will be allowed to make changes.
    """
    safe_link = utilities.create_safe_link(destination)
    data_dict = dict()
    msg = ""
    pp = pprint.PrettyPrinter(indent=4)
    precise_results = False
    parent_results = False
    results = ""
    if mode == "lookup":
        api_key = authentication.get_api_key_for_account("user@seclarity.io")
        db_results = utilities.get_subdomain_details_by_name(destination, api_key)
        if db_results is None:
            msg += "An error seems to have occurred."
        else:
            for subdomain_details in db_results:
                if subdomain_details["destinationName"] == destination:
                    if len(subdomain_details) > 1:
                        precise_results = True
                        results = pp.pformat(subdomain_details)
                        break
                else:
                    if len(subdomain_details) > 1:
                        child_results = True
                        results = pp.pformat(subdomain_details)
            if precise_results:
                msg += ("_NetworkSage_ has information about "
                        + safe_link
                        + "\nDetails:\n"
                        + "```"
                        + results
                        + "```"
                        )
            elif parent_results:
                msg += ("While _NetworkSage_ does not have information about "
                        + safe_link
                        + ", we do have results for a parent domain of it. Details:\n"
                        + "```"
                        + results
                        + "```"
                        )
            else:
                msg += ("_NetworkSage_ has no information about "
                        + safe_link
                        + ". If you know information and would like to add it, please type `/metadata add "
                        + destination
                        + "`"
                        )
    else:
        if userid in privileged_users.keys():
            change_occurred = False
            change_text = ""
            modal_json = get_modal()
            tags_json = get_metatags()
            finalized_modal_json = finalize_modal(tags_json, modal_json, destination)
            if finalized_modal_json is None:
                data_dict["text"] = "Failed to successfully prepare modal for `" + mode + "` mode."
                slack.send_reply_to_response_url(response_url, data_dict)
                return
            """Add and Update modes both attempt to change metadata, so we need to see (in either case) if there's
                already metadata for the thing that a user wants to change. If there is, we populate what we already
                know about the destination into the modal. If the user came in under 'add' mode, we let them know about
                the existing metadata and move them to 'update' mode.
            """
            api_key = authentication.get_api_key_for_account("user@seclarity.io")
            db_results = utilities.get_subdomain_details_by_name(destination, api_key)
            if db_results is None:
                data_dict["text"] = "We're having trouble communicating with _NetworkSage_. Please try again."
                slack.send_reply_to_response_url(response_url, data_dict)
                return
            existing_results = None
            for subdomain_details in db_results:
                if subdomain_details["destinationName"] == destination and len(subdomain_details) > 1:
                    existing_results = subdomain_details  # collect what we already have
                    if mode == "add":
                        data_dict["text"] = ("_NetworkSage_ already knows about "
                                             + destination
                                             + ". Populating known information and changing to `update` mode."
                                             )
                        mode = "update"
                    else:
                        data_dict["text"] = ("Populating known information for "
                                             + destination
                                             )
                    slack.send_reply_to_response_url(response_url, data_dict)
                    break
            if existing_results is None and mode == "update":
                data_dict["text"] = ("_NetworkSage_ *doesn't* know about "
                                     + destination
                                     + ". Changing to `add` mode."
                                     )
                mode = "add"
            if existing_results is not None:
                finalized_modal_json = populate_existing_metadata(finalized_modal_json, existing_results)
            # print("Trying to add", destination, "to details title")
            # finalized_modal_json["title"]["text"] += ("for "
            #                                        + destination
            #                                        )
            view_data = {"trigger_id": trigger_id
                , "view": finalized_modal_json
                         }
            view_id = slack.send_view_to_user(view_data)
            # ^ we handle the metadata saving when we receive the final data in the modal from the user
            if view_id is None:
                data_dict["text"] = ("Something went wrong while trying to prepare modal. Please try again.")
                slack.send_reply_to_response_url(response_url, data_dict)
                return
            # print("I'm here with view_id of", view_id)
        else:
            msg += "You are not authorized to add or update metadata. To request access, please contact @david"
    data_dict["text"] = msg
    slack.send_reply_to_response_url(response_url, data_dict)


def finalize_modal(tags_json, modal_json, destination_name):
    """Uses the tags JSON data to populate the modal JSON data for tag labels, selections, and descriptions
    """
    if tags_json is None or modal_json is None:
        return None
    try:
        modal_tags_data_section = copy.deepcopy(modal_json["blocks"][-2])
        """Tags data section should contain following data:
            {'type': 'input'
            , 'element': {'type': 'multi_static_select'
                        , 'placeholder': {'type': 'plain_text'
                                        , 'text': 'Select one or more options'
                                        , 'emoji': True
                                        }
                        , 'options': [{'text': {'type': 'plain_text'
                                                , 'text': '*this is plain_text text*'
                                                , 'emoji': True
                                                }
                                        , 'value': 'value-0'
                                        }]
                        , 'action_id': 'multi_static_select-action'
                        }
            , 'label': {'type': 'plain_text'
                        , 'text': 'Destination Tags'
                        , 'emoji': True
                        }
            }
        """
        modal_tags_hint_section = copy.deepcopy(modal_json["blocks"][-1])
        """Tags hint section should contain following data:
            {'type': 'context'
            , 'elements': [{'type': 'plain_text'
                            , 'text': 'Hint: Add tags here if you think this Destination falls into the categories available.'
                            , 'emoji': True
                            }]
            }
        """
    except:
        return None
    modal_tag_blocks_replacement = []  # this is where we'll now capture the replacement blocks that we need to add to the in-memory JSON of the modal
    try:
        """Now we need to iterate through our metatags (in the order they're stored in the tags JSON file) and populate
           a new copy of the tag contents with each tag type.
       """
        for tag_category_info in tags_json:
            # create a fresh copy of the sections so we don't overwrite
            fresh_modal_tags_data_section = copy.deepcopy(modal_tags_data_section)
            fresh_modal_tags_hint_section = copy.deepcopy(modal_tags_hint_section)

            modal_tag_name = fresh_modal_tags_data_section["label"]["text"]
            modal_tag_options = fresh_modal_tags_data_section["element"]["options"]
            modal_tag_action_name = fresh_modal_tags_data_section["element"]["action_id"]
            modal_tag_hint = fresh_modal_tags_hint_section["elements"][0]["text"]
            label = tag_category_info["humanReadableCategory"]
            category = tag_category_info["category"]
            hint = tag_category_info["hint"]
            modal_tag_name = label
            modal_tag_hint = hint
            """At this point, we have fresh copies of the three things we'll need to populate for each type of tag:
                tag_name (str of text to replace with the humanReadableCategory field)
                tag_options (list of dicts of dicts; each option we want to capture should be populated into these 
                [tag string in text field, increment of value in value field])
                tag_hint (str of text to replace with hint field)
            """
            all_tag_values = []
            """ Iterate through each category's tags and collect values """
            for tag in tag_category_info["tags"]:
                modal_tag_options[0]["text"]["text"] = tag
                modal_tag_options[0]["value"] = tag
                fresh_modal_tag_options = copy.deepcopy(modal_tag_options[0])
                all_tag_values += [fresh_modal_tag_options]
            modal_tag_options = all_tag_values  # collect all tags
            """ Save updated copies """
            fresh_modal_tags_data_section["element"]["options"] = modal_tag_options
            fresh_modal_tags_data_section["element"]["action_id"] = category
            fresh_modal_tags_hint_section["elements"][0]["text"] = hint
            fresh_modal_tags_data_section["label"]["text"] = label
            """For each tag category, add that to to the modal JSON"""
            modal_tag_blocks_replacement += [fresh_modal_tags_data_section]
            modal_tag_blocks_replacement += [fresh_modal_tags_hint_section]
    except:
        return None
    try:
        modal_json_blocks = modal_json["blocks"][
                            0:-2] + modal_tag_blocks_replacement  # we want to remove the placeholder blocks
        modal_json_blocks[0]["text"]["text"] = modal_json_blocks[0]["text"]["text"].replace("the Destination",
                                                                                            destination_name)
        modal_json["blocks"] = modal_json_blocks  # update the JSON with the new blocks
    except:
        return None
    return modal_json


def populate_existing_metadata(modal_json, existing_destination_metadata):
    """When we have existing metadata for a Destination, we use this function to update the modal with the information
        that already exists. The populated modal is returned to the user.
    """
    populated_modal_json = modal_json
    # print("In populate_existing_metadata, we want to put", existing_destination_metadata, "into", modal_json)
    # first, get all of the tags that actually have data
    existing_metadata_tags = dict()
    for metadata_item in existing_destination_metadata.keys():
        # print("Checking", metadata_item)
        if metadata_item.endswith("Tags") and len(existing_destination_metadata[metadata_item]) > 0:
            tag_name = metadata_item
            existing_metadata_tags[tag_name] = ast.literal_eval(existing_destination_metadata[tag_name])
    # print("Existing tags:", existing_metadata_tags)
    try:
        modal_json["submit"]["text"] = "Update"
    except:
        pass
    for block in modal_json["blocks"]:
        if block["type"] != "input":
            continue
        if block["element"]["type"] == "plain_text_input":  # these are required fields
            if block["element"]["action_id"] == "destination_title":
                block["element"]["initial_value"] = existing_destination_metadata[
                    "title"]  # add the initial value for title
            elif block["element"]["action_id"] == "destination_description":
                block["element"]["initial_value"] = existing_destination_metadata[
                    "description"]  # add the initial value for description
        elif block["element"]["type"] == "radio_buttons":  # add any relevance information
            if "relevance" in existing_destination_metadata.keys() and existing_destination_metadata["relevance"] != "":
                for rb_option in block["element"]["options"]:
                    # print("Checking radio button option", rb_option)
                    if rb_option["value"] == existing_destination_metadata["relevance"]:
                        block["element"]["initial_option"] = rb_option
        elif block["element"]["type"] == "multi_static_select":  # deal with all optional tags
            if block["element"][
                "action_id"] in existing_metadata_tags.keys():  # we already have some tags here, so populate them
                tag_category = block["element"]["action_id"]
                # if the tag that we have already saved isn't in the options list, add it to the options list
                known_tag_options = []
                initial_tags = []
                option_template = copy.deepcopy(block["element"]["options"][0])
                for option in block["element"]["options"]:
                    known_tag_options += [option["value"]]
                for tag_name in existing_metadata_tags[tag_category]:
                    if tag_name not in known_tag_options:
                        # print("Found a new tag", tag_name, "that wasn't in", known_tag_options)
                        option_template["text"]["text"] = tag_name
                        option_template["value"] = tag_name
                        block["element"]["options"] += [copy.deepcopy(option_template)]
                # now that we have all of the tags, prepopulate the modal with the ones we know
                for tag_option in block["element"]["options"]:
                    if tag_option["value"] in existing_metadata_tags[tag_category]:
                        initial_tags += [tag_option]
                if len(initial_tags) > 0:
                    block["element"]["initial_options"] = initial_tags
        else:
            print("Unsupported element", block)
    populated_modal_json = modal_json
    return populated_modal_json


def get_metatags():
    """Gets all of the metatags from our metatags JSON file.
    """
    try:
        with open("metadatascripts/metatags.json") as tags_file:
            return json.load(tags_file)
    except:
        return None


def get_modal():
    """Gets the Slack modal for use in interacting with metadata.
    """
    try:
        with open("metadatascripts/destination_modal.json") as modal_file:
            return json.load(modal_file)
    except:
        return None


def print_usage(command, response_url):
    response_dict = dict()
    if command == "sandbox-manual":
        response_dict["text"] = "```Usage: sandbox-manual submit <url of interest>```"
    elif command == "analyze-sample":
        response_dict["text"] = "```Usage: analyze-sample <UUID of NetworkSage sample>```"
    elif command == "analyze-destination":
        response_dict["text"] = "```Usage: analyze-destination <destination_name:port>```"
    elif command == "metadata":
        response_dict["text"] = "```Usage: metadata [lookup, add, update] <destination_name:port>```"
    slack.send_reply_to_response_url(response_url, response_dict)


def handle_metadata(**kwargs):
    """Decides what to do to handle valid commands.
    """
    user_info = kwargs["user_info"]
    userid = user_info["id"]
    metadata_dict = kwargs["metadata"]
    change_occurred = kwargs["change_occurred"]
    destination_name = kwargs["destination_name"]
    mode = kwargs["mode"]
    msg = ""
    for item in metadata_dict.keys():
        if not item.endswith("Tags"):
            continue
        else:
            if len(metadata_dict[item]) == 0:
                metadata_dict[item] = ""  # change from likely list to an empty string
    pp = pprint.PrettyPrinter(indent=4)
    change_text = pp.pformat(metadata_dict)  # Temporary
    if change_occurred:
        result_json = modify_metadata.save_destination_metadata_from_slack(destination_name, metadata_dict)
        if result_json["error"]:
            msg = result_json["body"]
            print("Error:", msg)  # TODO: get this back to the user
        else:
            mode_text = "an "
            if mode == "update":
                mode_text += mode
            elif mode == "add":
                mode_text += mode + "ition"
            msg = ("user <@"
                   + userid
                   + "> just made "
                   + mode_text
                   + " to _NetworkSage_! Details:\n"
                   + "```"
                   + "Destination name: "
                   + utilities.create_safe_link(destination_name)
                   + "\n"
                   + change_text
                   + "```"
                   )
            sent = slack.send_new_message(channel="#some_channel"
                                          , message_text=msg
                                          )
    else:
        msg = "Nothing is different, so no changes made."  # TODO: get this back to the user
        print(msg)
    return


def handle_command(**kwargs):
    """Decides what to do to handle valid commands.
    """
    command = kwargs["command"]
    text = kwargs["text"]
    response_url = kwargs["response_url"]
    userid = kwargs["userid"]
    trigger_id = kwargs["trigger_id"]
    msg = ""

    if text.startswith("help"):
        print_usage(command, response_url)
        return
    options = text.split()
    data_dict = dict()
    sandbox_results = dict()
    if command == "sandbox-manual":
        if "submit" in options or "fullAnalysis" in options:
            url = options[-1]
            data_dict[
                "text"] = "Calling manual sandbox with URL " + url + " in 5 seconds. Please go to sandbox to interact."
            slack.send_reply_to_response_url(response_url, data_dict)
            time.sleep(5)
            sandbox_results = interact_with_sandbox("manual", url)
        else:
            print_usage(command, response_url)
            return
        if "fullAnalysis" in options and sandbox_results is not None:
            data_dict["text"] = "Performing full analysis on results. This may take a moment."
            slack.send_reply_to_response_url(response_url, data_dict)
            testing.demo(sandbox_results["sample_info"]["uuid"], True)
    elif command == "analyze-sample":
        data_dict["text"] = "Analyzing sample."
        if len(options) > 1 and len(options[0]) not in [32, 100]:
            print_usage(command, response_url)
            return
        uuid = options[0]
        slack.send_reply_to_response_url(response_url, data_dict)
        testing.demo(uuid, True)
    elif command == "analyze-destination":
        if len(options) != 1 or ":" not in options[0]:
            print_usage(command, response_url)
            return
        dest_name = options[0].split(":")[0]
        if not utilities.validate_real_destination(dest_name):
            data_dict["text"] = "This doesn't seem to be a real destination."
            slack.send_reply_to_response_url(response_url, data_dict)
            return
        testing.test_destination_analysis(options[0], via_slack=True)
    elif command == "metadata":
        command_modes = ["lookup", "add", "update"]
        if 2 > len(options) >= 3 or options[0] not in command_modes:
            print_usage(command, response_url)
            return
        mode = options[0]
        destination = options[1]
        dest_name = destination.split(":")[0]
        if ":" not in destination:
            print_usage(command, response_url)
            return
        elif not utilities.validate_real_destination(dest_name):
            data_dict["text"] = "This doesn't seem to be a real destination."
            slack.send_reply_to_response_url(response_url, data_dict)
            return
        interact_with_metadata(mode, destination, userid, trigger_id, response_url)
    elif command == "sandbox-automated":
        data_dict["text"] = "This command is not yet implemented."
        slack.send_reply_to_response_url(response_url, data_dict)


def valid_command(command, text):
    """Determines if the command passed in is something that we handle. If not, returns False.
    """
    if command in ["sandbox-manual", "sandbox-automated", "analyze-sample", "analyze-destination", "metadata"]:
        return True
    return False


@networkSage_slackbot.route("/slack/metadata-endpoint", methods=["POST"])
def receive_interactivity():
    """Gets any interactive data from our metadata Slack command.
    """
    if "payload" in request.form.keys():
        user_data = json.loads(request.form["payload"])
        if user_data["type"] != "view_submission":
            return "FAIL"
        change_occurred = True
        try:
            print("Data:", user_data["view"]["blocks"][0])
            name_block = re.search('about .*:[0-9]{1,5} here', user_data["view"]["blocks"][0]["text"]["text"])
            try:
                destination = name_block.group(0)[6:-5]
            except:
                destination = user_data["view"]["blocks"][0]["text"]["text"].split("|")[-1].split(">")[0]
            #print("Destination data:", destination)
        except:
            msg = "!!!!!!!!!!!!!!!!!!!!Destination was not successfully captured!!!!!!!!!!!!!!!!!!!!"
            print(msg)
            destination = "higgledypiggledy.tld:443"  # TODO: replace with block data
        metadata_dict = {
            "title": ""
            , "description": ""
            , "relevance": ""
            , "destinationTags": []
            , "activityPurposeTags": []
            , "impactsTags": []
            , "threatTags": []
            , "attackVectorTags": []
            , "securityTags": []
            , "associatedAppOrServiceTags": []
            , "platformHintTags": []
        }
        for item in user_data["view"]["state"]["values"].keys():
            current_element = user_data["view"]["state"]["values"][item]
            if "destination_title" in current_element.keys():
                metadata_dict["title"] = current_element["destination_title"]["value"]
            if "destination_description" in current_element.keys():
                metadata_dict["description"] = current_element["destination_description"]["value"]
            if "relevance_choice" in current_element.keys():
                try:
                    metadata_dict["relevance"] = current_element["relevance_choice"]["selected_option"]["value"]
                except:
                    metadata_dict["relevance"] = ""
            if "destinationTags" in current_element.keys():
                try:
                    print(current_element["destinationTags"]["selected_options"])
                    for tag in current_element["destinationTags"]["selected_options"]:
                        metadata_dict["destinationTags"] += [tag["value"]]
                except:
                    metadata_dict["destinationTags"] = ""
            if "activityPurposeTags" in current_element.keys():
                try:
                    for tag in current_element["activityPurposeTags"]["selected_options"]:
                        metadata_dict["activityPurposeTags"] += [tag["value"]]
                except:
                    metadata_dict["activityPurposeTags"] = ""
            if "impactsTags" in current_element.keys():
                try:
                    for tag in current_element["impactsTags"]["selected_options"]:
                        metadata_dict["impactsTags"] += [tag["value"]]
                except:
                    metadata_dict["impactsTags"] = ""
            if "threatTags" in current_element.keys():
                try:
                    for tag in current_element["threatTags"]["selected_options"]:
                        metadata_dict["threatTags"] += [tag["value"]]
                except:
                    metadata_dict["threatTags"] = ""
            if "attackVectorTags" in current_element.keys():
                try:
                    for tag in current_element["attackVectorTags"]["selected_options"]:
                        metadata_dict["attackVectorTags"] += [tag["value"]]
                except:
                    metadata_dict["attackVectorTags"] = ""
            if "securityTags" in current_element.keys():
                try:
                    for tag in current_element["securityTags"]["selected_options"]:
                        metadata_dict["securityTags"] += [tag["value"]]
                except:
                    metadata_dict["securityTags"] = ""
            if "associatedAppOrServiceTags" in current_element.keys():
                try:
                    for tag in current_element["associatedAppOrServiceTags"]["selected_options"]:
                        metadata_dict["associatedAppOrServiceTags"] += [tag["value"]]
                except:
                    metadata_dict["associatedAppOrServiceTags"] = ""
            if "platformHintTags" in current_element.keys():
                try:
                    for tag in current_element["platformHintTags"]["selected_options"]:
                        metadata_dict["platformHintTags"] += [tag["value"]]
                except:
                    metadata_dict["platformHintTags"] = ""
        try:
            # if user_data["existing_metadata"] is not None:
            #    print("VS. original metadata:", user_data["existing_metadata"])
            #    if user_data["existing_metadata"] == metadata_dict:
            #        change_occurred = False # this is the only case where things didn't change
            slack_response_thread = threading.Thread(target=handle_metadata
                                                     , kwargs={"metadata": metadata_dict
                    , "user_info": user_data["user"]
                    , "view_id": user_data["view"]["id"]
                    , "change_occurred": change_occurred
                    , "destination_name": destination
                    , "mode": user_data["view"]["submit"]["text"].lower()
                                                               })
            msg = "Got your request. Preparing requested functionality."
            slack_response_thread.start()
        except:
            msg = "Request doesn't look good."
    else:
        msg = "Request doesn't look good."
    print(msg)
    status_code = Response(status=200)  # send bare acknowledgment back to client so modal correctly closes
    return status_code


@networkSage_slackbot.route("/slack/commands", methods=["POST"])
def receive_command():
    """Gets a Slack command from a user and dispatches the appropriate response.
    """
    # print("Full request:", request.form,"\nJSON", request.json, "\nHeaders:", request.headers)
    if not slack.validate_signing_secret(request):
        return "FAIL"  # fake request
    user_input = request.form
    # print("Inside slack commands function, here's what we received.",request.form)
    msg = ""
    if valid_command(user_input["command"][1:], user_input["text"]):
        slack_response_thread = threading.Thread(target=handle_command, kwargs={"command": user_input["command"][1:]
            , "text": user_input["text"]
            , "response_url": user_input["response_url"]
            , "userid": user_input["user_id"]
            , "trigger_id": user_input["trigger_id"]
                                                                                }
                                                 )
        msg = "Got your request. Preparing requested functionality."
        slack_response_thread.start()
    else:
        msg = "Request doesn't look good. Current options are:\n sandbox-manual submit <url>\nsandbox-automated submit <url>"
    return msg


def main():
    networkSage_slackbot.run(debug=False, host="0.0.0.0", port=5432)


if __name__ == "__main__":
    main()
