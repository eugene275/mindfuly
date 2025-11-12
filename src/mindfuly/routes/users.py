from fastapi import APIRouter

router = APIRouter(prefix="/users", tags=["Users"])

@router.get("/test")
def test():
    return {"status": "ok"}
