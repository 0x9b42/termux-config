import re

class Words:

    def __init__(self):
        self.db = {}

    def info(self):
        self.total_words()
        print(self.db)

    def add(self, sentence):
        sentence = sentence.lower()
        words = re.sub(r"[^'\w ]", '', sentence).split()

        for w in words:
            if w in self.db:
                self.db[w] += 1
            else:
                self.db[w] = 1

    def total_words(self):
        return 'total words'



word_db = Words()

word_db.add("hey yo, Bro! what's up? good.")
word_db.add("hey yo, Bro! what's up? nice.")

word_db.info()
