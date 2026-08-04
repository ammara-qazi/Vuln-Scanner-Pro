"""crawler.py - BFS web crawler that discovers pages, forms and parameters."""
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

logger = logging.getLogger("webvulnscanner.crawler")


@dataclass
class Page:
    url:        str
    url_params: List[str] = field(default_factory=list)
    forms:      List[dict] = field(default_factory=list)


def _same_origin(base: str, url: str) -> bool:
    b = urlparse(base)
    u = urlparse(url)
    return b.netloc == u.netloc


def _abs(base: str, href: str) -> Optional[str]:
    try:
        full = urljoin(base, href)
        p = urlparse(full)
        if p.scheme not in ("http", "https"):
            return None
        return full.split("#")[0]
    except Exception:
        return None


def _extract_params(url: str) -> List[str]:
    try:
        return list(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []


def _extract_forms(soup: BeautifulSoup, page_url: str) -> List[dict]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "") or page_url
        action = _abs(page_url, action) or page_url
        method = (form.get("method") or "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append({"name": name, "type": inp.get("type", "text")})
        if inputs:
            forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


class Crawler:
    def __init__(self, client, target: str, max_depth: int = 2,
                 max_pages: int = 30, progress_cb: Optional[Callable] = None):
        self.client     = client
        self.target     = target
        self.max_depth  = max_depth
        self.max_pages  = max_pages
        self.progress   = progress_cb or (lambda m: None)

    def crawl(self) -> List[Page]:
        visited: set = set()
        pages:   list = []
        queue: deque = deque([(self.target, 0)])

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            self.progress(f"[crawl] {url}")
            resp = self.client.get(url)
            if resp is None or resp.status_code >= 400:
                continue

            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct:
                continue

            soup = BeautifulSoup(resp.text, "lxml")
            page = Page(
                url=url,
                url_params=_extract_params(url),
                forms=_extract_forms(soup, url),
            )
            pages.append(page)

            if depth < self.max_depth:
                for a in soup.find_all("a", href=True):
                    link = _abs(url, a["href"])
                    if link and _same_origin(self.target, link) and link not in visited:
                        queue.append((link, depth + 1))

        return pages
