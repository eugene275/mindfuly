from fastapi import FastAPI
from src.mindfuly.routes import authorization, users, mood, spotify, weather

app = FastAPI(
    title="Mindfuly",
    version="1.0.0",
    decription="Handles mood logs, Spotify sesssions, weather context, and user authentication",
)


app.include_router(authorization.router)
app.include_router(users.router)
app.include_router(mood.router)
app.include_router(spotify.router)
app.include_router(weather.router)