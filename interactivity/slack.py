"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import hashlib
import hmac
import json
import logging
import sys
import time
import urllib.parse

import requests
from slack_sdk import WebClient  # pip3 install slack_sdk
from slack_sdk.errors import SlackApiError

from analysis import analysis

"""This module is not used in production.
"""

logger = logging.getLogger()
logger.setLevel(logging.INFO)
my_signing_secret = ""
my_token = ""
client = WebClient(token=my_token)  # os.environ["SLACK_BOT_TOKEN"])


def validate_signing_secret(incoming_request):
    timestamp = incoming_request.headers["X-Slack-Request-Timestamp"]
    if abs(time.time() - float(timestamp)) > 60 * 5:
        # The request timestamp is more than five minutes from local time.
        # It could be a replay attack, so let's ignore it.
        return False
    request_body = ""
    count = 0
    for item in incoming_request.form:
        if count != 0:
            request_body += "&" + item + "=" + urllib.parse.quote(incoming_request.form[item], safe="")
        else:
            request_body += item + "=" + incoming_request.form[item]
        count += 1
    sig_basestring = "v0:" + timestamp + ":" + request_body

    my_signature = "v0=" + hmac.new(
        key=my_signing_secret.encode(),
        msg=request_body.encode(),
        digestmod=hashlib.sha256).hexdigest()

    slack_signature = incoming_request.headers["X-Slack-Signature"]
    print("Does", slack_signature, "\nmatch", my_signature, "which is computed on data", request_body)

    if "team_domain=modified" not in request_body or "app_id=modified" not in request_body:
        return False
    return True


    if hmac.compare_digest(my_signature, slack_signature):
        # hooray, the request came from Slack!
        return True
    return False


def quit_if_error(response):
    if response is None:
        logging.info("Something failed while trying to communicate with Slack.")
        sys.exit(1)


def send_new_message(channel, message_text, block_data=None):
    response = None
    try:
        if block_data is not None:
            response = client.chat_postMessage(channel=channel, text=message_text, blocks=block_data)
        else:
            response = client.chat_postMessage(channel=channel, text=message_text)
        # print("Response's message text:", response["message"]["text"])
        # assert response["message"]["text"] == message_text
    except SlackApiError as e:
        # You will get a SlackApiError if "ok" is False
        assert e.response["ok"] is False
        assert e.response["error"]  # str like "invalid_auth", "channel_not_found"
        print(f"Got an error: {e.response['error']}")
    quit_if_error(response)
    return response


def send_thread_reply(channel, message_text, parent_ts):
    response = None
    try:
        response = client.chat_postMessage(channel=channel, text=message_text, thread_ts=parent_ts)
        # assert response["message"]["text"] == message_text
    except SlackApiError as e:
        # You will get a SlackApiError if "ok" is False
        assert e.response["ok"] is False
        assert e.response["error"]  # str like "invalid_auth", "channel_not_found"
        print(f"Got an error: {e.response['error']}")
    quit_if_error(response)
    return response


def send_reply_to_response_url(response_url, json_data):
    """This is used for when we have users that send us messages, and we want to respond back and forth with them.
    """

    request_headers = {"content-type": "application/json"
                       }
    request = requests.Request("POST", response_url, data=json.dumps(json_data), headers=request_headers)
    prepped = request.prepare()
    s = requests.Session()
    result = s.send(prepped)


def send_view_to_user(view_data):
    """Used for when we have users that request functionality that is served in a View, and we want to interact with
        them.
    """
    response_url = "https://slack.com/api/views.open"
    request_headers = {"Content-type": "application/json"
        , "Authorization": "Bearer " + my_token
                       }
    # pass along destination name and existing metadata (if any) for use in final steps.
    request = requests.Request("POST", response_url, data=json.dumps(view_data), headers=request_headers)
    prepped = request.prepare()
    s = requests.Session()
    result = s.send(prepped)
    if result.status_code == requests.status_codes.codes.ok:
        try:
            result_data = json.loads(result.text)
            # print("Result data:", result_data)
            if result_data["ok"]:
                return result_data["view"]["id"]  # ["logId"]
            else:
                print("Data wasn't okay. Details:", result_data)
                return None
        except:
            return None
    print("Status Code:", result.status_code)
    return None


def no_new_replies(channel_id, msg_id):
    reply = client.conversations_replies(channel=channel_id, ts=msg_id)
    if len(reply["messages"]) == 1:
        return True
    return False


def get_new_replies_for_thread(channel_id, msg_id):
    replies = client.conversations_replies(channel=channel_id, ts=msg_id)
    return replies["messages"][1:]


def process_message(link, channel_id, msg_id):
    print("Got a reply!")
    replies = get_new_replies_for_thread(channel_id, msg_id)
    action = "ignore"
    for reply in replies:
        answer = reply["text"].lower()
        if answer == "cancel":
            send_thread_reply(channel_id, "Canceling automated sandbox request and ignoring this destination.",
                              msg_id)
            action = answer
        else:
            send_thread_reply(channel_id, "I don't recognize your answer, so I'm ignoring it.", msg_id)
            action = "ignore"
        """
        if answer == "s":
            send_thread_reply(channel_id, "Submitting to sandbox", msg_id)
            all_evidence = collect_sandbox_evidence(args.fresh, link, result)
            return all_evidence
        elif answer == "p":
            send_thread_reply(channel_id, "(TODO) Preparing metadata to be saved to NetworkSage.", msg_id)
            print("TODO!")
        elif answer == "i":
            send_thread_reply(channel_id, "Ignoring "+link, msg_id)
        """
        break  # we only process the first response right now.
    return action


def send_notice(msg, args, link, result, evidence):
    # options = " You can choose 's' to submit to a semi-automated sandbox (which you'll need to interact with), 'p' to prepare metadata for saving to NetworkSage, or 'i' to ignore this result."
    options = " If no response from a human within 30 seconds, I will submit this to our automated sandbox. To cancel this action, respond to this message (as a thread) with 'cancel'."
    sent = send_new_message(channel="#some_channel", message_text=msg + options)
    msg_id = sent["ts"]
    channel_id = sent["channel"]
    done_waiting = False
    action = None
    while not done_waiting:
        if no_new_replies(channel_id, msg_id):
            time.sleep(30)
            done_waiting = True
            # TODO: Only wait up to 30 seconds
        else:
            done_waiting = True
            action = process_message(link, channel_id, msg_id)
    if action is None:
        if no_new_replies(channel_id, msg_id):
            action = "automate"
            send_thread_reply(channel_id,
                              "No response, so submitting to sandbox. Additional details should appear within a minute or two, depending on load.",
                              msg_id)
            results = analysis.collect_sandbox_evidence(args.fresh, "automated", link, result, args.slack, evidence,
                                                        channel=channel_id, thread=msg_id)
            if results is None:
                return results
            evidence = results
            # keep track of IDs to communicate with user
            evidence.other_metadata["channel_id"] = channel_id
            evidence.other_metadata["msg_id"] = msg_id
            return evidence
        else:
            action = process_message(link, channel_id, msg_id)
    if action == "ignore":
        return None
    elif action == "cancel":
        return None
    return None
