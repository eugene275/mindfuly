from fastapi import APIRouter

router = APIRouter(prefix="/authorization", tags=["Authorization"])

@router.get("/test")
def test():
    return {"status": "ok"}
