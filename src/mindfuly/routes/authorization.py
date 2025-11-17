from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from pydantic import BaseModel

from user_service_v2.models.user import get_user_repository_v2, UserRepositoryV2
from src.mindfuly.auth.jwt_utils import create_access_token, verify_token, get_current_user

router = APIRouter(prefix="/authorization", tags=["Authorization"])


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


@router.get("/test")
def test():
    return {"status": "ok"}


@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)
):
    """
    Authenticate user and return JWT token
    """
    # Get user from database
    user = await user_repo.get_by_name(login_data.username)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify password
    if not await user_repo.verify_password(user, login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token = create_access_token(
        data={"sub": user.name},
        expires_delta=timedelta(hours=24)
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)
):
    """
    OAuth2 compatible token login (for API clients)
    """
    user = await user_repo.get_by_name(form_data.username)
    
    if not user or not await user_repo.verify_password(user, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(
        data={"sub": user.name},
        expires_delta=timedelta(hours=24)
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/verify")
async def verify_current_token(current_user: str = Depends(get_current_user)):
    """
    Verify that the current token is valid
    """
    return {
        "valid": True,
        "username": current_user
    }


@router.post("/refresh", response_model=Token)
async def refresh_token(current_user: str = Depends(get_current_user)):
    """
    Refresh the access token for authenticated user
    """
    access_token = create_access_token(
        data={"sub": current_user},
        expires_delta=timedelta(hours=24)
    )
    
    return {"access_token": access_token, "token_type": "bearer"}