"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Application entry point for the FastAPI evaluation target.
"""

import jinja2
from fastapi import FastAPI

from routers import admin, public

app = FastAPI(title="Inventory API")
app.include_router(public.router)
app.include_router(admin.router)

templates = jinja2.Environment(autoescape=False)

BIND_HOST = "0.0.0.0"
BIND_PORT = 8000


@app.get("/")
async def index():
    """Service banner."""
    return {"service": "inventory", "version": "1.4.0"}


@app.get("/render")
async def render(name: str = "world"):
    """Render the greeting template."""
    template = templates.from_string("<p>Hello {{ name }}</p>")
    return {"html": template.render(name=name)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=BIND_HOST, port=BIND_PORT)
