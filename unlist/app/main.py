"""FastAPI application factory. Served on 127.0.0.1 only; POSTs must come from the app's
own origin so a web page you happen to visit cannot drive it."""

from __future__ import annotations

import sys
import threading
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from unlist import paths
from unlist.app.jobs import JobRunner

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.runner = JobRunner()
    app.state.runner.start()
    yield
    app.state.runner.stop()


def _same_origin(request: Request) -> bool:
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site:
        return fetch_site in ("same-origin", "none")
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if value:
            host = urlsplit(value).netloc
            return host == request.headers.get("host", "")
    return False


def create_app() -> FastAPI:
    app = FastAPI(title="unlist", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def csrf_guard(request: Request, call_next):
        if request.method == "POST" and not _same_origin(request):
            return PlainTextResponse("Forbidden: cross-site request", status_code=403)
        return await call_next(request)

    from unlist.app import views

    app.include_router(views.router)
    return app


def main(argv: list[str] | None = None) -> None:
    import argparse

    import uvicorn

    from unlist.mcp.server import _load_dotenv

    parser = argparse.ArgumentParser(prog="unlist-app")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    _load_dotenv()
    paths.data_dir()
    url = f"http://127.0.0.1:{args.port}/"
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    print(f"unlist dashboard at {url} (localhost only; Ctrl-C to stop)")
    uvicorn.run(create_app(), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
