"""
Execute test with: cd hhvm-fuzzing/web_fuzzer/ && pytest tests/test_parser.py -v
"""
import pytest
from os.path import dirname
from unittest.mock import Mock
from urllib.parse import urlparse, urlunparse, urlencode
from bs4 import BeautifulSoup

import webFuzz.parser as p
import webFuzz.detector as d
from webFuzz.environment import env
from webFuzz.node import Node
from webFuzz.types import HTTPMethod, Arguments

# environment initialization
margs = Mock(wraps=Arguments)
margs.unique_anchors = False
env.args = margs
env.instrument_args = Mock()
env.args.injection_type = "xss"
# p.logging.Logger = Mock(wraps=p.logging.Logger)

# @pytest.fixture(scope='module')
# def parser():
#     parser_obj = p.Parser(["<script>alert(121234)</script>", "<body onload=alert(121234)>"])

#     yield parser_obj

@pytest.fixture(scope='module')
def from_node():
    node = Node(url="http://localhost/wp-admin/admin-ajax.php",
                method=HTTPMethod.GET,
                params={HTTPMethod.GET: {'s': "21213vreg<body onload=alert(121234)>234dfw"},
                        HTTPMethod.POST: {}},
                )
    yield node

@pytest.fixture(scope='module')
def detector():
    det = d.Detector()
    yield det

@pytest.fixture(scope='module')
def aiohttp_req():

    # Create Mock object of type aiohttp.ClientResponse
    f = open(dirname(__file__) + "/test_html.html", "r")
    html = f.read()
    f.close()

    async def return_comock():
        return html

    req = Mock()
    req.text = return_comock
    req.request_info.real_url = "http://localhost/wp-admin/admin-ajax.php"

    yield req

@pytest.fixture(scope='module')
def soup_html():
    f = open(dirname(__file__) + "/test_html.html", "r")
    html = f.read()
    f.close()

    yield BeautifulSoup(html, "html5lib")

@pytest.mark.parametrize('url_test',
                         [
                             "#",
                             "",
                             "?"
                         ]
                         )
def test_set_default_query(from_node, url_test):
    self_req = urlparse(from_node.url)
    self_req = self_req._replace(query=urlencode(from_node.params[HTTPMethod.GET], doseq=True))
    self_req = self_req.query

    test = p.Parser.set_default_query(from_node.url_object, urlparse(url_test))
    assert urlunparse(test) == "?"+self_req

@pytest.mark.parametrize('url_test, url_correct',
                         [
                             ("/action/logout.php", "http://localhost/action/logout.php"),
                             ("", "http://localhost"),
                             ("/action", "http://localhost/action")
                         ]
                         )
def test_set_default_hostname(from_node, url_test, url_correct):
    test = p.Parser.set_default_domain(urlparse(from_node.url), urlparse(url_test))
    assert urlunparse(test) == url_correct
    
@pytest.mark.parametrize('url_test, url_correct',
                         [
                             ("http://localhost/", "http://localhost/"),
                             ("logout.php", "http://localhost/wp-admin/logout.php"),
                             ("?hey=there", "http://localhost/wp-admin/admin-ajax.php?hey=there")
                         ]
                         )
def test_parse_url(from_node, url_test, url_correct):
    test = p.Parser.normalise_url(from_node.url_object, urlparse(url_test))
    assert test != None
    assert urlunparse(test) == url_correct

@pytest.mark.asyncio
async def test_look_for_xss(detector, caplog, soup_html, from_node):
    # Should only return one possible rxss. The rxss is in 'tib' parameter is htmlencoded in test_html.html
    with caplog.at_level(logger="webFuzz.parser", level='WARNING'):
        detector.xss_scanner(from_node, soup_html)
        assert len(caplog.records) == 1
        assert "Possible xss found" in \
               caplog.text

@pytest.mark.asyncio
async def test_parse_anchors_links(caplog, soup_html, from_node):
    with caplog.at_level(logger="webFuzz.parser", level='WARNING'):
        actual_nodes = p.Parser.parse_anchors(soup_html, from_node)

        expected_nodes = [
            Node(url="http://localhost/wp-admin/admin.php",
                 method=HTTPMethod.GET,
                 params={HTTPMethod.GET: {'page': ['mailpoet-newsletter-editor'],
                                          'id': ['1</script><script>alert("hello");</script>']},
                         HTTPMethod.POST: {}},
                ),
            Node(url="http://localhost/wp-admin/admin.php",
                 method=HTTPMethod.GET,
                 params={HTTPMethod.GET: {'page': ['ninja-forms'],
                                          'success': ["'</script><script>alert(123);</script>"]},
                         HTTPMethod.POST: {}},
                ),
            Node(url="http://localhost/index.php",
                 method=HTTPMethod.GET,
                 params={HTTPMethod.GET: {'p': ['1745'], 'Display_FAQ': ['</script><svg/onload=alert(/XSS/)>']},
                         HTTPMethod.POST: {}},
                ),
            Node(url="http://localhost/wp-admin/admin-ajax.php",
                 method=HTTPMethod.GET,
                 params={HTTPMethod.GET: {'test': ["default"]},
                         HTTPMethod.POST: {}},
                )
        ]

        for node in actual_nodes:
            assert node in expected_nodes

@pytest.mark.asyncio
async def test_parse_forms(caplog, soup_html, from_node):
    with caplog.at_level(logger="webFuzz.parser", level='WARNING'):
        actual_nodes = p.Parser.parse_forms(soup_html, from_node)

        expected_nodes = [
            Node(url="http://localhost/wp-admin/root-ajax.php",
                 method=HTTPMethod.POST,
                 params={HTTPMethod.GET: {},
                         HTTPMethod.POST: {
                             'action': ['nf_ajax_submit'],
                             'formData': [
                                 '{"id":"1", "fields": { "1": { "value" : "<body onload=alert(document.cookie)>", '
                                 '"id": 1}}}']
                         }},
                ),
            Node(url="http://localhost/wp-admin/user-ajax.php",
                 method=HTTPMethod.POST,
                 params={HTTPMethod.GET: {},
                         HTTPMethod.POST: {
                             'answer': ["x ", ""],
                             'question_type': [""],
                             'points': ['0', '1', '2'],
                             'action': ['chainedquiz_ajax'],
                             'chainedquiz_action': ['answer'],
                             'total_questions': ['1v4918<script>alert(document.cookie)</script>eyjfw']
                         }},
                )
        ]

        for node in actual_nodes:
            if node.method == HTTPMethod.POST:
                assert node in expected_nodes
