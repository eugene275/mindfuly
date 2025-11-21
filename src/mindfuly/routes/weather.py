from fastapi import APIRouter, HTTPException
import httpx, os

router = APIRouter(prefix="/weather", tags=["Weather"])

WEATHER_API_KEY = os.getenv("WEATHER_API_KEY")

@router.get("")
async def get_weather(lat: float, lon: float):

    print("API KEY:", WEATHER_API_KEY)
    print("LAT:", lat)
    print("LON:", lon)

    
    if not WEATHER_API_KEY:
        raise HTTPException(status_code=500, detail="Weather API Key not configured")
    
    url = "https://api.openweathermap.org/data/2.5/weather"

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params={
            "lat": lat,
            "lon": lon,
            "appid": WEATHER_API_KEY,
            "units": "metric"
        })

    print("WEATHER RESPONSE:", resp.status_code, resp.text)

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail="Weather API error")
    
    return resp.json()

