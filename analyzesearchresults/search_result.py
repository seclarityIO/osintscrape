"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io) and Vladimir Budilov (vladimir@seclarity.io).

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
class SearchResult():
    def __init__(self, term):
        self.search_term = term
        self.ads_text = ""
        self.total_results = -1  # how many results were returned for this term
        self.top_results = dict()  # dictionary with result number as key and a tuple of (title, link, text_snippet) as value
        self.inferred_topics = dict()

    def getTopicsFromSearch(self):
        """Takes search results and performs LDA on the bigrams and trigrams to
            figure out what is most likely the topic of the search results. Currently turned off.
        """
        import nltk
        import pandas as pd
        from textblob import TextBlob
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.pipeline import make_pipeline
        from sklearn.decomposition import LatentDirichletAllocation
        # at least some of the below libraries are needed the first time
        # nltk.download("punkt")
        # nltk.download("wordnet")
        # nltk.download("averaged_perceptron_tagger")
        # nltk.download("maxent_ne_chunker")
        # nltk.download("words")
        # nltk.download("stopwords")
        stop_words = nltk.corpus.stopwords.words("english")
        stop_words.remove("not")  # keep "not"
        corpus = []
        # discard the link (causes topics to be less clear when in corpus)
        results = [corpus.extend([val[0]] + [val[2]]) for val in list(self.top_results.values())]
        """Not implemented right now.
        print("Results:", results)
        print("C:", c)
        for element in results:
            corpus += [" ".join(element)]
        print("Corpus:", corpus)
        """
        df = pd.DataFrame(corpus)
        df.columns = ["searchResults"]
        df["polarity"] = df["searchResults"].apply(lambda x: TextBlob(x).polarity)
        df["subjective"] = df["searchResults"].apply(lambda x: TextBlob(x).subjectivity)

        # Topic modeling of bigrams/trigrams
        tfidf_vectorizer = TfidfVectorizer(stop_words=stop_words, ngram_range=(2, 3))
        model = LatentDirichletAllocation(n_components=3)  # num of topics to create
        pipe = make_pipeline(tfidf_vectorizer, model)
        pipe.fit(df["searchResults"])
        feature_names = tfidf_vectorizer.get_feature_names()
        n_top_words = 3
        tmp_dict = dict()
        for topic_idx, topic in enumerate(model.components_):
            tmp_dict[topic_idx] = ", ".join([feature_names[i]
                                             for i in topic.argsort()[:-n_top_words - 1:-1]])
        self.inferred_topics = tmp_dict
