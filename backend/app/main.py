"""FastAPI application factory for IsSomethingPhisy."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import health, scan


def create_app() -> FastAPI:
    app = FastAPI(
        title="IsSomethingPhisy",
        description="Phishing URL detector — paste a link, find out if it's phishy.",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Dev mode — allow all origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(scan.router)
    app.include_router(health.router)

    return app


app = create_app()
