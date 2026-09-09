"""
Project Mathra - Root Entrypoint Forwarder
Points to backend.main:app for backwards compatibility and ease of deployment.
"""

from backend.main import app

if __name__ == "__main__":
    import uvicorn
    from backend.core.config import get_settings

    settings = get_settings()
    uvicorn.run(
        "backend.main:app",
        host=settings.proxy_host,
        port=settings.proxy_port,
        reload=False,
    )