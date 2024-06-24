import copy
import re
import esprima

from aiohttp      import ClientSession, ClientResponse
from bs4          import BeautifulSoup, element
from typing       import AsyncIterator, Set, Dict, Any
from contextlib   import asynccontextmanager

from lib.core.agent import agent
from lib.core.data import conf, kb
from lib.core.common import average, extractRegexResult, getFilteredPageContent, listToStrValue, randomStr, removeReflectiveValues, stdev
from lib.core.enums import PAYLOAD
from lib.core.settings import CANDIDATE_SENTENCE_MIN_LENGTH, MAX_TIME_RESPONSES, MIN_TIME_RESPONSES, MIN_VALID_DELAYED_RESPONSE, SLEEP_TIME_MARKER, TIME_STDEV_COEFF
from lib.core.threads import getCurrentThreadData
from lib.parser.html import htmlParser

from .environment import env, stats
from .misc        import get_logger, longest_str_match
from .types       import XSSConfidence, SQLIConfidence, HTTPMethod, UnimplementedHttpMethod, InvalidContentType, InvalidHttpCode, XSSConfidence, FORMAT_EXCEPTION_STRINGS
from .node        import Node

urlAttributes = [
    "action",
    "cite",
    "data",
    "formaction",
    "href",
    "longdesc",
    "manifest",
    "poster",
    "src"
]

class Detector():
    def __init__(self):
        self.vuln_count = 0

        self._flagged_elements_xss: Dict[XSSConfidence, Dict[str,Set[str]]] = {
            XSSConfidence.LOW : {},
            XSSConfidence.MEDIUM : {},
            XSSConfidence.HIGH : {}
        }

        self._flagged_elements_sql: Dict[SQLIConfidence, Dict[str,Set[str]]] = {
            SQLIConfidence.LOW : {},
            SQLIConfidence.MEDIUM : {},
            SQLIConfidence.HIGH : {}
        }

    @staticmethod
    def js_ast_traversal(node: Any) -> XSSConfidence:
        # TODO: manage javascript label statements
        # TODO: manage code in eval statements
        
        # print(str(type(node)))
        conf = XSSConfidence.NONE

        if type(node) == list:
            for stmt in node:
                res = Detector.js_ast_traversal(stmt)
                if res == XSSConfidence.HIGH:
                    return XSSConfidence.HIGH
                else:
                    conf = max(res, conf)

        elif 'esprima.nodes.CallExpression' in str(type(node)):
             if node.callee.name in ["alert", "prompt", "confirm"]:

                res = Detector.js_ast_traversal(node.arguments)
                if res > XSSConfidence.NONE:
                    # 0xdeadbeef found in one of its arguments
                    return XSSConfidence.HIGH
                else:
                    confidence = max(res, confidence)

        elif 'esprima.nodes.TaggedTemplateExpression' in str(type(node)):
            if node.quasi.type == 'TemplateLiteral' and \
               node.tag.name in ["alert", "prompt", "confirm"]:

                res = Detector.js_ast_traversal(node.quasi.quasis)
                if res > XSSConfidence.NONE:
                    # 0xdeadbeef found in one of its arguments
                    return XSSConfidence.HIGH
                else:
                    confidence = max(res, confidence)

        if "esprima.nodes" in str(type(node)):
            for attr in dir(node):
                res = Detector.js_ast_traversal(getattr(node, attr))
                if res == XSSConfidence.HIGH:
                    return XSSConfidence.HIGH
                else:
                    confidence = max(res, confidence)

        if type(node) == str:
            if longest_str_match(node, "0xdeadbeef") >= 5:
                confidence = max(XSSConfidence.LOW, confidence)

        return confidence

    @staticmethod
    def handle_script(raw_code: str) -> XSSConfidence:
        try:
            script = esprima.parseScript(raw_code)
            return Detector.js_ast_traversal(script.body)
        except:
            # fallback to weak method
            if longest_str_match(raw_code, "0xdeadbeef") >= 5:
                return XSSConfidence.LOW
            
            return XSSConfidence.NONE

    @staticmethod
    def handle_attr(name:str, value: str) -> XSSConfidence:
        result = XSSConfidence.NONE

        if name.lower() in urlAttributes and \
           value[:11].lower() == "javascript:":
            # strip leading javascript
            value = value[11:]
            result = Detector.handle_script(value)

        elif name[:2] == "on":
            result = Detector.handle_script(value)


        return result
        
    def record_response_XSS(self, 
                        node: Node, 
                        confidence: XSSConfidence, 
                        id_: str,
                        elem_type: str, 
                        value: str) -> None:
        logger = get_logger(__name__)

        if confidence == XSSConfidence.NONE:
            return

        if node.url not in self._flagged_elements_xss[confidence]:
            self._flagged_elements_xss[confidence][node.url] = set()

        if id_ not in self._flagged_elements_xss[confidence][node.url]:

            if not self._flagged_elements_xss[XSSConfidence.HIGH].get(node.url, []):
                logger.warning("Possible xss found with confidence %s. Type: %s, Value: %s, Url: %s, Node: %s",
                                confidence, elem_type, value, node.full_url, node)
                if confidence == XSSConfidence.HIGH:
                    self.vuln_count += 1

            self._flagged_elements_xss[confidence][node.url].add(id_)

            if node.is_mutated:
                # reward parent node with a sink found
                node.parent_request.has_sinks = True

    def record_response_SQLi(self, 
                        node: Node, 
                        confidence: SQLIConfidence, 
                        method: HTTPMethod,
                        param: str,
                        value: str) -> None:
        logger = get_logger(__name__)
        
        if confidence == SQLIConfidence.NONE:
            return

        if node.url not in self._flagged_elements_sql[confidence]:
            self._flagged_elements_sql[confidence][node.url] = set()
        
        id_ = hash((method, param))
        if id_ not in self._flagged_elements_sql[confidence][node.url]:
            if not self._flagged_elements_sql[SQLIConfidence.HIGH].get(node.url, []):
                logger.warning("Possible SQLi found with confidence %s. Method: %s, Param: %s, Value: %s, Url: %s, Node: %s",
                                confidence, method, param, value, node.full_url, node)
                if confidence == SQLIConfidence.HIGH:
                    self.vuln_count += 1

            self._flagged_elements_sql[confidence][node.url].add(id_)

            if node.is_mutated:
                # reward parent node with a sink found
                node.parent_request.has_sinks = True
        
        

    def should_analyze(self, id_: str, url: str, content: str) -> bool:
        if id_ not in self._flagged_elements_xss[XSSConfidence.HIGH].get(url, []) and \
            longest_str_match(content, "0xdeadbeef") >= 5:
            return True
        
        return False

    @staticmethod
    def xss_precheck(raw_html: str) -> bool:
        if longest_str_match(raw_html, "0xdeadbeef") >= 5:
            return True
        return False

    def xss_scanner(self,
                    node: Node,
                    html: BeautifulSoup) -> XSSConfidence:
        logger = get_logger(__name__)

        confidence = XSSConfidence.NONE
        logger.info("Performing XSS detection...")
        
        for elem in html.find_all():
            if type(elem) != element.Tag:
                continue

            id_ = elem.name + "/" + elem.attrs.get('id', "")

            if elem.name.lower() == "script":
                print(elem.string)
                if not self.should_analyze(id_, node.url, elem.string):
                    continue

                result = Detector.handle_script(elem.string)

                self.record_response_XSS(node,
                                        result, 
                                        id_, 
                                        elem_type="Script", 
                                        value=elem.string)

                confidence = max(result, confidence)

            for (attr_name, attr_value) in elem.attrs.items():
                param_id = id_ + "/" + attr_name

                if not self.should_analyze(param_id, node.url, attr_value):
                    continue

                result = Detector.handle_attr(attr_name, attr_value)

                self.record_response(node,
                                     result, 
                                     param_id, 
                                     elem_type=f"Attribute {attr_name}", 
                                     value=attr_value)
                confidence = max(result, confidence)

        node.xss_confidence = confidence
        return confidence

    def setClientSession(self, session: ClientSession) -> None:
        self._session = session

    @asynccontextmanager
    async def http_send(self, new_request: Node) -> AsyncIterator[ClientResponse]:
        logger = get_logger(__name__)

        if new_request.method == HTTPMethod.GET:
            aiohttp_send = self._session.get
        elif new_request.method == HTTPMethod.POST:
            aiohttp_send = self._session.post
        else:
            logger.error("Unimplemented HTTP method")
            raise UnimplementedHttpMethod(new_request.method)

        logger.info("Perform SQL Injection testing request: %s", new_request.url)

        async with aiohttp_send(new_request.url,
                                params=new_request.params[HTTPMethod.GET],
                                data=new_request.params[HTTPMethod.POST],
                                trace_request_ctx=new_request) as r:

            stats.total_requests += 1

            if r.content_type and r.content_type.lower() != 'text/html':
                raise InvalidContentType(r.content_type)

            if r.status >= 400:
                logger.info('Got code %d from %s', r.status, r.url)

                if env.args.ignore_404 and r.status == 404:
                    raise InvalidHttpCode(404)

                if env.args.ignore_4xx:
                    raise InvalidHttpCode(r.status)

            yield r

    @staticmethod
    def pageComparison(url, page, originalPage, negative_logic) -> tuple[bool, float]:
        if page == originalPage:
            return True, 1.0
        seqMatcher = getCurrentThreadData().seqMatcher

        key = (hash(page), hash(originalPage))
        seqMatcher.set_seq1(page or "")
        seqMatcher.set_seq2(originalPage or "")

        if key in kb.cache.comparison:
            ratio = kb.cache.comparison[key]
        else:
            ratio = round(seqMatcher.quick_ratio() if not kb.heavilyDynamic else seqMatcher.ratio(), 3)

        if key:
            kb.cache.comparison[key] = ratio
        if kb.matchRatio.get(url) is None:
            kb.matchRatio[url] = ratio

        if ratio > 0.98:
            return False if not negative_logic else True, ratio
        elif ratio < 0.02:
            return True if not negative_logic else False, ratio
        else:
            ret = (ratio - kb.matchRatio[url]) > 0.05
            return ret if not negative_logic else not ret, ratio

    async def sqli_scanner(self, node: Node, html: str) -> SQLIConfidence:
        logger = get_logger(__name__)

        for httpmethod in [HTTPMethod.GET, HTTPMethod.POST]:
            for key, value in node.param_sqli_type[httpmethod].items():
                if len(value) == 0:
                    continue
                
                confidence = SQLIConfidence.NONE
                if value[0] == -1:
                    self.sqli_heuristic_check(node, html, key, httpmethod)
                else:
                    test = conf.tests[value[0]]
                    boundary = conf.boundaries[value[1]]
                    where = test.where[value[2]]
                    method = list(test.response.keys())[0]
                    prefix = boundary.prefix or ""
                    suffix = boundary.suffix or ""
                    clause = test.clause
                    comment = agent.getComment(test.request) if len(conf.boundaries) > 1 else None
                    if method == PAYLOAD.METHOD.COMPARISON:
                        # Generate payload used for comparison
                        def genCmpPayload():
                            sndPayload = agent.cleanupPayload(test.response.comparison, origValue=None)

                            # Forge response payload by prepending with
                            # boundary's prefix and appending the boundary's
                            # suffix to the test's ' <payload><comment> '
                            # string
                            boundPayload = agent.prefixQuery(sndPayload, prefix, where, clause)
                            boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                            cmpPayload = agent.payload(newValue=boundPayload, where=where)

                            return cmpPayload
                        
                        pay = genCmpPayload()
                        check_params = copy.deepcopy(node.parent_request.params)
                        check_params[httpmethod][key] = list(map(lambda x: x + pay, check_params[httpmethod][key]))
                        check_node = Node(url=node.url,
                                        method=node.method,
                                        params=check_params,
                                        param_sqli_type=node.param_sqli_type,
                                        parent_request=node.parent_request)
                        
                        negative_logic = where == PAYLOAD.WHERE.NEGATIVE

                        async with self.http_send(node.parent_request) as r:
                            originalResponse, originalCode = await r.text(), r.status

                        async with self.http_send(check_node) as r:
                            falseResponse, falseCode = await r.text(), r.status
                            falseResponse = removeReflectiveValues(falseResponse, check_node.params[httpmethod][key][0])

                        if not negative_logic:
                            try:
                                ratio = 1.0
                                seqMatcher = getCurrentThreadData().seqMatcher
                                seqMatcher.set_seq1(originalResponse or "")
                                seqMatcher.set_seq2(falseResponse or "")
                                ratio *= seqMatcher.quick_ratio()

                                if ratio == 1.0:
                                    continue
                                else:
                                    confidence = SQLIConfidence.LOW
                            except (MemoryError, OverflowError):
                                pass
                        
                        trueResponse = removeReflectiveValues(html, node.params[httpmethod][key][0])
                        
                        trueResult, trueRatio = self.pageComparison(node.url, trueResponse, originalResponse, negative_logic)
                        if trueResult and trueResponse != falseResponse:
                            confidence = SQLIConfidence.MEDIUM

                            falseResult, falseRatio = self.pageComparison(node.url, falseResponse, originalResponse, negative_logic)
                            if not falseResult:
                                if negative_logic:
                                    boundPayload = agent.prefixQuery(str(randomStr(10)), prefix, where, clause)
                                    boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                                    errorPayload = agent.payload(newValue=boundPayload, where=where)

                                    check_params[httpmethod][key] = list(map(lambda x: errorPayload, check_params[httpmethod][key]))
                                    async with self.http_send(node) as r:
                                        errorResponse = await r.text()
                                    
                                    errorResult = self.pageComparison(errorResponse, originalResponse, negative_logic)
                                    if errorResult:
                                        confidence = SQLIConfidence.NONE
                                        continue
                                
                                confidence = SQLIConfidence.HIGH
                            else:
                                originalSet = set(getFilteredPageContent(originalResponse, True, "\n").split("\n"))
                                trueSet = set(getFilteredPageContent(trueResponse, True, "\n").split("\n"))
                                falseSet = set(getFilteredPageContent(falseResponse, True, "\n").split("\n"))

                                if originalSet == trueSet != falseSet:
                                    candidates = trueSet - falseSet

                                    if candidates:
                                        candidates = sorted(candidates, key=len)
                                        for candidate in candidates:
                                            if re.match(r"\A[\w.,! ]+\Z", candidate) and ' ' in candidate and candidate.strip() and len(candidate) > CANDIDATE_SENTENCE_MIN_LENGTH:
                                                confidence = SQLIConfidence.HIGH
                                                continue

                                               
                    elif method == PAYLOAD.METHOD.GREP:
                        check = agent.cleanupPayload(test.response.grep, origValue=None)
                        async with self.http_send(node) as r:
                            response = await r.text()
                            headers = r.headers
                        response = removeReflectiveValues(response, node.params[httpmethod][key][0])
                        output = extractRegexResult(check, response, re.DOTALL | re.IGNORECASE)
                        output = output or extractRegexResult(check, listToStrValue((headers[key] for key in list(headers.keys())) if headers else None), re.DOTALL | re.IGNORECASE)

                        if output:
                            confidence = SQLIConfidence.LOW
                            result = output == '1'
                            if result:
                                confidence = SQLIConfidence.HIGH
                        
                    elif method == PAYLOAD.METHOD.TIME:
                        responseTimekey = hash((node.url, node.method))
                        
                        if (len(kb.responseTimes.get(responseTimekey, []))) < MIN_TIME_RESPONSES:
                            if responseTimekey not in kb.responseTimes:
                                kb.responseTimes[responseTimekey] = []
                            cleanParams = copy.deepcopy(node.params)
                            cleanParams[httpmethod][key] = list(map(lambda x: '', cleanParams[httpmethod][key]))
                            timecheckNode = Node(url=node.url,
                                                method=node.method,
                                                params=cleanParams,
                                                param_sqli_type=node.param_sqli_type,
                                                parent_request=node.parent_request)
                            while len(kb.responseTimes.get(responseTimekey, [])) < MIN_TIME_RESPONSES:
                                async with self.http_send(timecheckNode) as r:
                                    kb.responseTimes[responseTimekey].append(timecheckNode.exec_time)
                                    if len(kb.responseTimes[responseTimekey]) > MAX_TIME_RESPONSES:
                                        kb.responseTimes[responseTimekey] = kb.responseTimes[responseTimekey][-MAX_TIME_RESPONSES // 2:]


                        deviation = stdev(kb.responseTimes.get(responseTimekey, []))
                        lowerStdLimit = average(kb.responseTimes[responseTimekey]) + TIME_STDEV_COEFF * deviation

                        # 99.9999999997440% of all non time-based SQL injection affected
                        # response times should be inside +-7*stdev([normal response times])
                        # Math reference: http://www.answers.com/topic/standard-deviation
                        trueParams = copy.deepcopy(node.params)
                        trueParams[httpmethod][key] = list(map(lambda x: agent.adjustLateValues(x), trueParams[httpmethod][key]))
                        trueNode = Node(url=node.url,
                                        method=node.method,
                                        params=trueParams,
                                        param_sqli_type=node.param_sqli_type,
                                        parent_request=node.parent_request)
                        async with self.http_send(trueNode) as r:
                            trueDelayed = (trueNode.exec_time >= max(MIN_VALID_DELAYED_RESPONSE, lowerStdLimit))
                        
                        if trueDelayed:
                            # Extra step for false positives
                            if SLEEP_TIME_MARKER in response:
                                falseParams = copy.deepcopy(node.params)
                                falseParams[httpmethod][key] = list(map(lambda x: x.replace(SLEEP_TIME_MARKER, 0), falseParams[httpmethod][key]))
                                falseNode = Node(url=node.url,
                                                method=node.method,
                                                params=falseParams,
                                                param_sqli_type=node.param_sqli_type,
                                                parent_request=node.parent_request)
                                async with self.http_send(falseNode) as r:
                                    falseDelayed = (falseNode.exec_time >= max(MIN_VALID_DELAYED_RESPONSE, lowerStdLimit))
                                
                                if falseDelayed:
                                    continue

                                async with self.http_send(trueNode) as r:
                                    trueDelayed = (trueNode.exec_time >= max(MIN_VALID_DELAYED_RESPONSE, lowerStdLimit))
                                    if trueDelayed:
                                        confidence = SQLIConfidence.HIGH

                    self.record_response_SQLi(node, confidence, httpmethod, key, node.params[httpmethod][key][0])

    def sqli_heuristic_check(self, node: Node, html: str, key, httpmethod) -> bool:
        logger = get_logger(__name__)
        logger.info("Performing Heuristic SQLi detection...")

        confidence = SQLIConfidence.NONE

        if htmlParser(html) != None:
            confidence = SQLIConfidence.HIGH

        def _(page):
            return any(_ in (page or "") for _ in FORMAT_EXCEPTION_STRINGS)
        
        casting = _(html)
        
        if casting:
            confidence = SQLIConfidence.HIGH
        
        self.record_response_SQLi(node, confidence, httpmethod, key, node.params[httpmethod][key][0])