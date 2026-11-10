"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Unauthenticated routes.
"""

import os
import sqlite3
import subprocess

import requests
import yaml
from fastapi import APIRouter, Request

from cache import cache_key, content_etag, sample_requests

router = APIRouter()

DB = "catalog.db"
UPSTREAM = "https://inventory.internal/api"


@router.get("/catalog/search")
async def search(q: str = ""):
    """Search the product catalog."""
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title FROM items WHERE title LIKE '%" + q + "%'")
    return {"results": cursor.fetchall(), "key": cache_key("search", q)}


@router.get("/catalog/item/{item_id}")
async def item_detail(item_id: str):
    """Return one catalog item."""
    with open(os.path.join("catalog", item_id + ".yml")) as handle:
        return yaml.load(handle.read(), Loader=yaml.Loader)


@router.get("/convert")
async def convert(expr: str = "1+1"):
    """Evaluate a unit-conversion expression."""
    return {"value": eval(expr)}


@router.get("/thumbnail")
async def thumbnail(source: str = ""):
    """Generate a thumbnail for an uploaded image."""
    subprocess.run(f"convert {source} -resize 100x100 /tmp/thumb.png", shell=True)
    return {"path": "/tmp/thumb.png"}


@router.get("/upstream/status")
async def upstream_status():
    """Proxy the upstream inventory health endpoint."""
    response = requests.get(f"{UPSTREAM}/health", verify=False, timeout=5)
    return {"upstream": response.status_code}


@router.get("/metrics/sample")
async def metrics_sample(request: Request, size: int = 10):
    """Return a sample of recent request log entries."""
    entries = getattr(request.app.state, "log", [])
    return {"sample": sample_requests(entries, size)}


@router.get("/ping")
async def ping():
    """Liveness probe."""
    payload = b"ok"
    return {"status": "ok", "etag": content_etag(payload)}
