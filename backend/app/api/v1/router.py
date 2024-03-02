from fastapi.routing import APIRouter

from app.api.v1.auth.controllers import router as auth_router
from app.api.v1.cohort.controllers import router as cohort_router
from app.api.v1.content.controllers import router as content_router
from app.api.v1.facebook.controllers import router as facebook_router
from app.api.v1.health import router as health_router
from app.api.v1.inbox.controllers import router as inbox_router
from app.api.v1.instagram.controllers import router as instagram_scraping_router
from app.api.v1.kraken.router import router as kraken_router
from app.api.v1.misc.controllers import router as misc_router
from app.api.v1.qrcode_generator.controllers import router as qrcode_generator_router
from app.api.v1.search.controllers import router as search_router
from app.api.v1.slack.controllers import router as slack_router
from app.api.v1.social.controllers import router as social_router
from app.api.v1.social.instagram.controllers import router as instagram_router
from app.api.v1.social.youtube.controllers import router as youtube_router
from app.api.v1.url_shortener.controllers import router as url_shortener_router
from app.api.v1.user.controllers import router as user_router
from app.api.v1.utm.controllers import router as utm_router
from app.api.v1.workspace.controllers import router as workspace_router

api_router = APIRouter(prefix="/v1")

api_router.include_router(health_router, tags=["health"], prefix="/health")
api_router.include_router(misc_router, tags=["misc"], prefix="/misc")
api_router.include_router(auth_router, tags=["auth"], prefix="/auth")
api_router.include_router(user_router, tags=["user"], prefix="/user")
api_router.include_router(search_router, tags=["search"], prefix="/search")
api_router.include_router(workspace_router, tags=["workspace"], prefix="/workspace")
api_router.include_router(slack_router, tags=["slack"], prefix="/slack")
api_router.include_router(
    instagram_scraping_router,
    tags=["instagram"],
    prefix="/instagram",
)
api_router.include_router(kraken_router, tags=["kraken"], prefix="/kraken")
api_router.include_router(facebook_router, tags=["facebook"], prefix="/facebook")
api_router.include_router(utm_router, tags=["utm"], prefix="/utm")
api_router.include_router(
    url_shortener_router,
    tags=["url_shortener"],
    prefix="/url_shortener",
)
api_router.include_router(
    qrcode_generator_router,
    tags=["qrcode_generator"],
    prefix="/qrcode_generator",
)
api_router.include_router(cohort_router, tags=["cohort"], prefix="/cohort")
api_router.include_router(content_router, tags=["content"], prefix="/content")

# Social Controllers

api_router.include_router(social_router, tags=["social"], prefix="/social")
api_router.include_router(youtube_router, tags=["youtube"], prefix="/social/youtube")
api_router.include_router(
    instagram_router,
    tags=["instagram"],
    prefix="/social/instagram",
)

api_router.include_router(inbox_router, tags=["inbox"], prefix="/inbox")
