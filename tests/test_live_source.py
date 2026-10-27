"""Live runs read the scenario's own reference by default, so Tavily does real work without the visitor typing a URL."""
import pytest

from shakedown.live import resolve_source
from shakedown.research import Source, TavilyError


class Tav:
    def __init__(self, readable):
        self.readable, self.extracts, self.searches = readable, [], []

    def extract(self, url):
        self.extracts.append(url)
        if url not in self.readable:
            raise TavilyError(f"could not extract {url}")
        return Source(url=url, title=url, content="page", retrieved_at="2026-10-27T00:00:00Z", via="extract")

    def search(self, query, max_results=5, include_domains=None):
        self.searches.append((query, max_results))
        return []


SCENARIO = {"reference_urls": ["https://twitter.com/x", "https://example.org/report", "https://example.org/other"]}


def test_the_first_readable_reference_is_chosen_and_read_only_once():
    tav = Tav({"https://example.org/report", "https://example.org/other"})
    url, client = resolve_source(tav, SCENARIO, None)

    assert url == "https://example.org/report"
    assert client.extract(url).content == "page"
    assert tav.extracts == ["https://twitter.com/x", "https://example.org/report"]
    client.search("q", max_results=8)
    assert tav.searches == [("q", 8)]


def test_an_explicit_address_is_used_as_given_with_the_normal_client():
    tav = Tav(set())
    assert resolve_source(tav, SCENARIO, "https://mine.example/r") == ("https://mine.example/r", tav)
    assert tav.extracts == []


@pytest.mark.parametrize("tavily, scenario", [(None, SCENARIO), (Tav(set()), {"reference_urls": []})])
def test_without_a_client_or_a_reference_the_run_has_no_web_source(tavily, scenario):
    assert resolve_source(tavily, scenario, None)[0] is None


def test_when_no_reference_is_readable_the_run_falls_back_to_the_description():
    assert resolve_source(Tav(set()), SCENARIO, None)[0] is None
