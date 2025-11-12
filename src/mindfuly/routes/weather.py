from fastapi import APIRouter

router = APIRouter(prefix="/weather", tags=["Weather"])

@router.get("/test")
def test():
    return {"status": "ok"}
