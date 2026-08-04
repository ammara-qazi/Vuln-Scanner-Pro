"""http_client.py - rate-limited requests.Session wrapper."""
import time
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("webvulnscanner.http")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class RateLimitedClient:
    def __init__(self, delay: float = 0.3, timeout: int = 10, cookie: str = ""):
        self.delay   = delay
        self.timeout = timeout
        self._last   = 0.0

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        if cookie:
            self.session.headers["Cookie"] = cookie

        retry = Retry(total=2, backoff_factor=0.3,
                      status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://",  adapter)
        self.session.mount("https://", adapter)

    def _wait(self):
        elapsed = time.time() - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.time()

    def get(self, url: str, **kwargs):
        self._wait()
        try:
            r = self.session.get(url, timeout=self.timeout,
                                 allow_redirects=True, **kwargs)
            return r
        except Exception as e:
            logger.debug("GET %s failed: %s", url, e)
            return None

    def post(self, url: str, data=None, **kwargs):
        self._wait()
        try:
            r = self.session.post(url, data=data, timeout=self.timeout,
                                  allow_redirects=True, **kwargs)
            return r
        except Exception as e:
            logger.debug("POST %s failed: %s", url, e)
            return None
