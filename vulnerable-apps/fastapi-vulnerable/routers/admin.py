"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Administrative routes. Access is mediated by FastAPI dependencies.
"""

import pickle
import subprocess

from fastapi import APIRouter, Depends, Request

from cache import disk_usage, evict
from security import get_current_user, verify_admin, verify_api_key

router = APIRouter()

REPORT_TEMPLATE = "/srv/reports/{name}.html"


@router.post("/admin/restore", dependencies=[Depends(verify_admin)])
async def restore(request: Request):
    """Restore operator state from an uploaded snapshot."""
    blob = await request.body()
    return {"restored": str(pickle.loads(blob))}


@router.get("/admin/logs")
async def read_logs(name: str = "app", user=Depends(get_current_user)):
    """Tail an operator log file."""
    output = subprocess.check_output("tail -n 50 /var/log/" + name, shell=True)
    return {"log": output.decode(), "user": user.get("id")}


@router.get("/admin/disk", dependencies=[Depends(verify_admin)])
async def disk():
    """Report cache disk usage."""
    return {"usage": disk_usage()}


@router.post("/admin/cache/evict", dependencies=[Depends(verify_api_key)])
async def cache_evict(key: str):
    """Drop a single cache entry."""
    evict(key)
    return {"evicted": key}


@router.get("/admin/export")
async def export(name: str = "summary", user=Depends(get_current_user)):
    """Return the path of a generated report."""
    assert isinstance(name, str)
    return {"path": REPORT_TEMPLATE.format(name=name)}
