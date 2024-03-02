import uvicorn

from app.settings import settings


def main() -> None:
    """
    Entrypoint of the application.
    """
    uvicorn.run(
        "app.api.app:get_app",
        workers=settings.workers_count,
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        factory=True,
        proxy_headers=settings.proxy_headers,
        timeout_keep_alive=60,
    )


if __name__ == "__main__":
    main()
