"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import logging
import threading
import uuid

from flask import Flask, request

import constants
import evidence_collector
from display import display


log_meta = threading.local()
log_meta.logId = "na"
log_meta.subId = "na"
log_meta.sampleId = "na"

app = Flask(__name__)

old_factory = logging.getLogRecordFactory()
def record_factory(*args, **kwargs):

    record = old_factory(*args, **kwargs)
    record.logId = log_meta.logId
    record.subId = log_meta.subId
    record.sampleId = log_meta.sampleId

    return record

l = logging.getLogger("App")
logging.setLogRecordFactory(record_factory)

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(name)s - logId=%(logId)s subId=%(subId)s sampleId=%(sampleId)s message=%(message)s",
    level=logging.INFO)


@app.route("/ping", methods=['GET'])
def health_check():
    # l.info("Checking if service is healthy")
    return "pong!"


@app.route("/samples/<sampleId>/summary", methods=['GET'])
def sample_summary(sampleId):
    """

    :return:
    """
    sub_id = request.headers.get('subId')
    log_meta.logId = uuid.uuid4().hex
    log_meta.subId = sub_id
    log_meta.sampleId = sampleId

    l.info("message=In the summary endpoint")

    logging.setLogRecordFactory(record_factory)

    if sampleId is None:
        l.error("message=No sampleId specified. Quitting.")
        return {"errorMessage": "No sample UUID specified. Quitting.", "error": True}
    try:
        if request.headers.get("apikey") is None:
            l.error("message=No apikey provided. Quitting.")
            return {"errorMessage": "No API key provided. Quitting.", "error": True}
        else:
            user_apikey = str(request.headers.get("apikey"))
    except:
        l.error("message=Error occurred while trying to get apikey header. "
                        "Quitting.")
        return {"errorMessage": "Error occurred while trying to get API key. Quitting.", "error": True}

    try:
        l.info(" message=Getting summary info..starting with the evidence")
        evidence = evidence_collector.EvidenceCollector(sampleId)
        l.info(" message=Running get_sample_summary with evidence -> " + str(evidence))
        summary_data = display.get_sample_summary(sampleId,
                                                  incoming_evidence=evidence,
                                                  apikey=user_apikey
                                                  )
        if summary_data is None:
            l.error("message=We had no summary data for this sample.")
            return {
                "errorMessage": "No summary data found for sample. This may occur if the sample was empty, or if you do not have access to the sample data.",
                "error": True
            }
        msg = ""
        for item in summary_data.keys():
            msg += "*" + item.capitalize() + ":* " + summary_data[item] + "\n"

        l.info("message=Returning summary " + str(msg))
    except Exception as e:
        l.error("Couldn't process the request", e)
        return {"errorMessage": "Couldn't process the request", "error": True}

    return {"body": summary_data}


@app.route("/samples/<sampleId>/categorization", methods=['GET'])
def categorization(sampleId):
    """

    :return:
    """
    sub_id = request.headers.get('subId')
    log_meta.logId = uuid.uuid4().hex
    log_meta.subId = sub_id
    log_meta.sampleId = sampleId
    if sampleId is None:
        l.error("message=No sample UUID specified. Quitting.")
        return {"errorMessage": "No sample UUID specified. Quitting.", "error": True}

    try:
        if request.headers.get("apikey") is None:
            l.error("message=No apikey provided. Quitting.")
            return {"errorMessage": "No API key provided. Quitting.", "error": True}
        else:
            user_apikey = str(request.headers.get("apikey"))
    except:
        l.error("message=Error occurred while trying to get apikey header. Quitting.")
        return {"errorMessage": "Error occurred while trying to get API key. Quitting.", "error": True}
    try:
        evidence = evidence_collector.EvidenceCollector(sampleId)
        categorized_activity_data = display.get_categorized_activity_groups(sampleId,
                                                                            incoming_evidence=evidence,
                                                                            apikey=user_apikey
                                                                            )
        if categorized_activity_data is None:
            l.error("message=We had no categorization data for this sample.")
            return {
                "errorMessage": "No categorization data found for sample. This may occur if the sample was empty, or if you do not have access to the sample data.",
                "error": True
            }
    except Exception as e:
        l.error("message=Couldn't process the request", e)
        return {"errorMessage": "Couldn't process the request", "error": True}

    return {"body": categorized_activity_data}


if __name__ == "__main__":
    l.info("Starting the service")
    app.run(debug=False, host='0.0.0.0', port=constants.FLASK_APP_PORT)
