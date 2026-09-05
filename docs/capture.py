"""Regenerate the README screenshots.

    pip install playwright && playwright install chromium
    uvicorn main:app --port 8000 &
    python docs/capture.py                    # everything
    python docs/capture.py --skip-scorecard   # skip the 32-scenario re-run

CLI output is rendered through Rich's HTML export, then screenshotted, so the
images in the README are produced from real runs rather than mocked up.
"""
from __future__ import annotations

import contextlib
import io
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console  # noqa: E402
from rich.terminal_theme import TerminalTheme  # noqa: E402

import demo as D  # noqa: E402
from config import get_settings  # noqa: E402

IMG = ROOT / "docs" / "img"
IMG.mkdir(parents=True, exist_ok=True)

THEME = TerminalTheme(
    (13, 17, 23), (230, 237, 243),
    [(13, 17, 23), (248, 81, 73), (63, 185, 80), (210, 153, 34),
     (88, 166, 255), (188, 140, 255), (57, 197, 187), (230, 237, 243)],
    [(110, 118, 129), (255, 123, 114), (86, 211, 100), (227, 179, 65),
     (121, 192, 255), (210, 168, 255), (86, 214, 204), (255, 255, 255)],
)

PAD = """
<style>
 html{background:#0d1117;}
 body{margin:0;padding:26px 30px;background:#0d1117;width:max-content;}
 pre{margin:0!important;font-size:13.5px!important;line-height:1.45!important;}
 code{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace!important;}
</style>
"""


class Quiet(Console):
    """Console with the live status spinner disabled, so captures stay clean."""

    def status(self, *args, **kwargs):
        return contextlib.nullcontext()


def render_cli(fn, name: str, width: int, tmp: pathlib.Path) -> pathlib.Path:
    console = Quiet(record=True, width=width, file=io.StringIO(), force_terminal=True)
    D.console = console
    fn()
    path = tmp / f"{name}.html"
    console.save_html(str(path), inline_styles=True, theme=THEME)
    path.write_text(path.read_text().replace("</head>", PAD + "</head>"))
    return path


SKIP_SCORECARD = "--skip-scorecard" in sys.argv


def main() -> None:
    from playwright.sync_api import sync_playwright

    settings = get_settings()
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        pages = {
            "cli-contrast": render_cli(
                lambda: (D.banner(settings), D.show_contrast("consent", settings)),
                "cli-contrast", 92, tmp),
            "cli-scorecard": render_cli(
                lambda: D.show_scorecard(settings), "cli-scorecard", 116, tmp),
        }

        with sync_playwright() as p:
            browser = p.chromium.launch()

            for name, html in pages.items():
                page = browser.new_page(viewport={"width": 1700, "height": 900},
                                        device_scale_factor=2)
                page.goto(html.as_uri())
                page.wait_for_timeout(300)
                page.locator("body").screenshot(path=str(IMG / f"{name}.png"))
                page.close()
                print("wrote", IMG / f"{name}.png")

            page = browser.new_page(viewport={"width": 1340, "height": 940},
                                    device_scale_factor=2)
            page.goto("http://127.0.0.1:8000")
            page.wait_for_selector(".acard")
            # A sticky header is painted at its scroll offset in full-page
            # screenshots, so it lands in the middle of the image. Pin it.
            page.add_style_tag(content=".topbar{position:static!important}")
            page.wait_for_timeout(900)

            page.screenshot(path=str(IMG / "web-hero.png"))
            print("wrote", IMG / "web-hero.png")

            # Live agent console, with the poisoned listing's hidden text revealed.
            page.locator(".prod.poison .revealbtn").first.click()
            page.click("#send")
            page.wait_for_selector("#verdict .verdict", timeout=240_000)
            page.wait_for_timeout(1200)
            page.locator("#liveSec").screenshot(path=str(IMG / "web-live-agent.png"))
            print("wrote", IMG / "web-live-agent.png")

            page.locator(".acard", has_text="Consent-capture poisoning").first.click()
            page.click("#run")
            page.wait_for_selector("#stage .pane", timeout=120_000)
            page.wait_for_timeout(2200)   # let the staggered pipeline finish
            page.locator("#stageSec").screenshot(path=str(IMG / "web-contrast.png"))
            print("wrote", IMG / "web-contrast.png")
            page.locator(".flowbox").screenshot(path=str(IMG / "web-flow.png"))
            print("wrote", IMG / "web-flow.png")

            if SKIP_SCORECARD:
                print("skipped web-scorecard.png (--skip-scorecard)")
                browser.close()
                return
            page.click("#score")
            page.wait_for_selector("#scoreout table.score", timeout=300_000)
            page.wait_for_timeout(1400)
            page.locator("#scoreSec").screenshot(path=str(IMG / "web-scorecard.png"))
            print("wrote", IMG / "web-scorecard.png")

            browser.close()


if __name__ == "__main__":
    main()
