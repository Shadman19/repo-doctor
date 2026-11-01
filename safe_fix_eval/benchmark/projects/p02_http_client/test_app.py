# Toy project: builds HTTP requests (no network calls are made).
import requests


def build_search_request(term):
    req = requests.Request("GET", "https://example.com/search", params={"q": term})
    return req.prepare()


def test_query_string_is_encoded():
    prepared = build_search_request("a b")
    assert prepared.url == "https://example.com/search?q=a+b"


def test_method_is_get():
    assert build_search_request("x").method == "GET"
