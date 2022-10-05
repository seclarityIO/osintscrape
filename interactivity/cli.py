"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
from analysis import analysis


def interact_via_cli(msg, args, link, result, evidence):
    # pync.notify(msg, title="OSINT Analyzer")
    print(msg)
    print(result, "needs more analysis to increase our confidence before we save it as",
          result["category"] + ". Sending it to fully-automated sandbox.")
    answer = input("Should we submit (Y/N)? ")
    if answer == "Y":
        success = analysis.collect_sandbox_evidence(args.fresh, "automated", link, result, args.slack, evidence,
                                                    channel=None, thread=None)
        if not success:
            return None
