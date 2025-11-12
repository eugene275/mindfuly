from fastapi import APIRouter

router = APIRouter(prefix="/spotify", tags=["Spotify"])

@router.get("/test")
def test():
    return {"status": "ok"}
