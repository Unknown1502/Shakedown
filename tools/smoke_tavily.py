"""Live Tavily check: one extract and one search (2-3 credits). Prints sizes and URLs only, never the key."""
import sys

from shakedown.config import load_dotenv
from shakedown.research import Tavily, TavilyError

URL = "https://www.mdsec.co.uk/2019/02/macros-and-more-with-sharpshooter-v2-0/"


def main() -> int:
    load_dotenv()
    try:
        tv = Tavily.from_env()
        src = tv.extract(URL)
        print(f"extract ok: {src.url} chars={len(src.content)} at {src.retrieved_at}")
        found = tv.search("AMSI bypass registry AmsiEnable reg.exe", max_results=3)
        print(f"search ok: {len(found)} results")
        for s in found:
            print(f"  {s.score} {s.url}")
        return 0
    except TavilyError as exc:
        print(f"TAVILY FAILED: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
