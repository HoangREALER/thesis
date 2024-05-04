from webFuzz.mutator import MutatorSQL
from webFuzz.fuzzer import setPaths, loadPayloads, loadBoundaries, _setKnowledgeBaseAttributes
from lib.core.enums import PAYLOAD
from lib.core.option import conf


conf.tests = []
conf.boundaries = []
setPaths()
loadPayloads()
loadBoundaries()
_setKnowledgeBaseAttributes()

hmm = MutatorSQL.add_sqli_payload('lol', ['lol'])
print(hmm)

print(list(conf.tests[14].response.keys())[0])
for test in conf.tests:
    if PAYLOAD.WHERE.REPLACE in list(test.where):
        print(conf.tests.index(test))