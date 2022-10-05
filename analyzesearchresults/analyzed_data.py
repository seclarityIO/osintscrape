"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
class AnalyzedData():
    def __init__(self, term, was_secondary_analysis=False):
        self.category = ""
        self.risk = ""
        self.score = 0  # 0 to 10, 10 being most interesting
        self.has_riot = False  # IP reputation service from GreyNoise -- currently not used
        self.is_big_business = False  # businesses that are more likely to be targeted with scams
        """ Preparation of evidence storage """
        self.evidence = dict()  # dict per search term. Keys are the topics we most run into as confusing, and each dict entry has a list of tuples where score is second item in tuple.
        self.evidence["totalResults"] = []
        self.evidence["pageHasNoTextSnippet"] = []
        self.evidence["advertisements"] = []
        self.evidence["securityThreat"] = []
        self.evidence["trackingSite"] = []
        self.evidence["potentialVector"] = []
        self.evidence["potentialImpact"] = []
        self.evidence["urlShortener"] = []
        self.evidence["pupThreat"] = []
        self.evidence["business"] = []
        self.evidence["domainForIP"] = []
        self.evidence["lowRelevanceTopResults"] = []
        self.domains_mentioned_in_security_results = set()
        self.likely_seo_attack = False  # capture if we think the site is trying to hide via SEO
        self.first_security_threat = -1  # first result labeled as a security threat
        self.referenced_in_results = False
        self.all_scores = []
        self.print_top_results = False
        self.has_secondary_analysis = False
        self.was_secondary_analysis = was_secondary_analysis
        self.term = term
        self.top_result = None
        self.total_results = 0
        self.final_text = ""
        self.should_label_destination = False
        self.title = ""
        self.possible_topic = None

    def __str__(self):
        return (str(self.__class__)
                + ":"
                + str(self.__dict__)
                )
