from fastapi import Depends, HTTPException, Request, Response, Cookie
from fastapi.responses import RedirectResponse
from nicegui import ui, app
from pydantic import parse_obj_as
from contextlib import contextmanager
import logging
import copy
from datetime import datetime, timedelta
from typing import Optional

from user_service_v2.models.user import get_user_repository_v2, UserRepositoryV2
from src.shared.models import get_mood_log_repository_v2, MoodLogRepositoryV2
from src.mindfuly.auth.jwt_utils import create_access_token, verify_token

logger = logging.getLogger('uvicorn.error')

# Middleware to check authentication
async def require_auth(username: str = None):
    """Check if user is authenticated via JWT token in localStorage"""
    # Get token from JavaScript localStorage
    token = await ui.run_javascript('localStorage.getItem("token")', timeout=1.0)
    
    if not token:
        ui.navigate.to('/login')
        return None
    
    try:
        token_username = verify_token(token)
        
        # If a specific username is required, verify it matches
        if username and token_username != username:
            ui.notify('Unauthorized access', color='red')
            ui.navigate.to('/login')
            return None
            
        return token_username
    except HTTPException:
        await ui.run_javascript('localStorage.clear()')
        ui.navigate.to('/login')
        return None


@ui.page('/home')
async def home_page():
    with ui.column().classes('mx-auto'):
        with ui.row().classes('w-full justify-center items-center px-4 mb-4'):
            ui.label('Mindfuly').classes('text-2xl font-bold')

        with ui.row().classes('w-full justify-between items-center mt-32 gap-4'):
            ui.button('Login', on_click=lambda: ui.navigate.to('/login')).classes('bg-blue-500')
            ui.button('Signup', on_click=lambda: ui.navigate.to('/signup')).classes('bg-blue-500')


@ui.page("/login")
async def login_page(user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)):
    with ui.column().classes('mx-auto'):
        with ui.row().classes('w-full justify-center items-center px-4 mb-4'):
            ui.label('Login Page').classes('text-2xl font-bold mb-4')

        with ui.row().classes('w-full justify-center items-center'):
            username_input = ui.input('Username').classes('mb-2')
            password_input = ui.input('Password', password=True).classes('mb-4')

            error_label = ui.label().classes('text-red-500 mt-2')
            error_label.visible = False

            async def handle_login():
                user = await user_repo.get_by_name(username_input.value)

                if user == None:
                    ui.notify('Not a valid user!', color='red')
                    return

                if await user_repo.verify_password(user, password_input.value):
                    # Create JWT token
                    access_token = create_access_token(
                        data={"sub": username_input.value},
                        expires_delta=timedelta(hours=24)
                    )
                    
                    # Store token using JavaScript localStorage directly
                    await ui.run_javascript(f'''
                        localStorage.setItem('token', '{access_token}');
                        localStorage.setItem('username', '{username_input.value}');
                    ''')
                    
                    ui.notify('Login successful!', color='green')
                    ui.navigate.to(f"/users/{username_input.value}/home")
                    
                else:
                    error_label.text = "Invalid password. Please try again."
                    error_label.visible = True
                    password_input.value = ""
                    password_input.focus()

            ui.button('Login', on_click=handle_login).classes('mt-4')
            password_input.on('keydown.enter', handle_login)


@ui.page("/signup")
async def signup_page(user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)):
    with ui.column().classes('mx-auto'):
        with ui.row().classes('w-full justify-center items-center px-4 mb-4'):
            ui.label('Signup Page').classes('text-2xl font-bold mb-4')

        with ui.row().classes('w-full justify-center items-center'):
            username_input = ui.input('Username').classes('mb-2')
            email_input = ui.input('Email').classes('mb-2')
            password_input = ui.input('Password').classes('mb-4')
            
            async def handle_signup():
                if not username_input.value or not email_input.value or not password_input.value:
                    ui.notify('Please fill in all fields.', color='red')
                    return

                result = await user_repo.create(username_input.value, email_input.value, password_input.value, tier=1)
                if not result:
                    ui.notify('User already exists.', color='red')
                    return
                
                ui.notify('Signup Successful! Please log in.')
                ui.navigate.to('/login')

            ui.button('Signup', on_click=handle_signup).classes('mt-4')


@ui.page('/')
async def root_page():
    ui.navigate.to('/home')


@ui.page("/admin/users/")
async def user_overview_page(user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)):
    
    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.navigate.to('/home')
    
    with ui.column().classes('mx-auto w-full max-w-6xl p-4'):
        with ui.row().classes('w-full justify-between items-center mb-6'):
            ui.label('User Overview').classes('text-2xl font-bold')
            ui.button('Refresh', on_click=lambda: ui.navigate.reload(), icon='refresh').classes('bg-blue-500')
            ui.button('Logout', on_click=handle_logout, icon='logout').classes('bg-red-500')
        
        
        users = await user_repo.get_all()
        
        with ui.row().classes('w-full mb-4'):
            ui.label(f'Total Users: {len(users)}').classes('text-lg font-semibold')

        with ui.column().classes('w-full gap-4'):
            for user in users:
                with ui.card().classes('w-full p-4'):
                    with ui.row().classes('w-full justify-between items-center'):
                        with ui.column().classes('flex-1'):
                            ui.label(f'Username: {user.name}').classes('text-lg font-bold')
                            ui.label(f'Email: {user.email}').classes('text-gray-600')
                            ui.label(f'ID: {user.id}').classes('text-gray-600')


@ui.page("/users/{username}/home")
async def user_home_screen(username: str, user_repo: UserRepositoryV2 = Depends(get_user_repository_v2), mood_log_repo = Depends(get_mood_log_repository_v2)):
    # Verify user is authenticated and accessing their own page
    authenticated_user = await require_auth(username)
    if not authenticated_user:
        return
    
    user = await user_repo.get_by_name(username)
    if not user: 
        ui.label("User not found.")
        return
    
    # Navbar with logout
    with ui.header().classes('justify-between items-center px-4 py-6 hover:shadow-lg transition-all duration-200'):
        ui.label('Mindfuly - Your Daily Wellness Tracker').classes('text-2xl font-bold')
        with ui.row().classes("gap-15 items-center"):
            ui.link("Overview", f"/users/{username}/home").classes("text-white text-lg no-underline")
            ui.link("Journal", f"/users/{username}/journal").classes("text-white text-lg no-underline")
            ui.link("My Analytics", f"/users/{username}/analytics").classes("text-white text-lg no-underline")
            ui.link("Settings", f"/users/{username}/settings").classes("text-white text-lg no-underline")
            ui.button('Logout', on_click=lambda: handle_logout(), icon='logout').classes('bg-red-500 ml-4')

    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.notify('Logged out successfully', color='green')
        ui.navigate.to('/home')

    with ui.column().classes('w-full items-center mt-10 mb-8'):
        ui.label(f"Welcome, {username}!").classes('text-4xl font-bold text-center mb-1')

    with ui.row().classes("w-full max-w-7xl justify-center gap-10 mx-auto items-stretch"):
        # Mood Log
        with ui.card().classes("basis-1/2 p-4 shadow-md rounded-2xl border items-center h-full"):
            ui.label("Today's Mood Log").classes("text-2xl font-bold mb-3 text-center")

            with ui.card().classes("w-full items-center"):
                ui.label("How are you feeling today?").classes("text-lg text-gray-600 font-semibold mb-6 text-center")
                
                with ui.row().classes("justify-center gap-25 mb-3 text-2xl"):
                    ui.label("😞")
                    ui.label("🙁")
                    ui.label("😐")
                    ui.label("🙂")
                    ui.label("😄")

                with ui.column().classes('items-center w-full'):
                    mood_slider = ui.slider(min=1, max=5, value=5).classes("w-full")
                    ui.label().bind_text_from(mood_slider, 'value').classes("text-xl font-bold mt-4 text-center")

            with ui.card().classes("w-full items-center"):
                ui.label("How pumped are you today?").classes("text-lg text-gray-600 font-semibold mb-6 text-center")
                
                with ui.row().classes("justify-center gap-25 mb-3 text-2xl"):
                    ui.label("😴")
                    ui.label("🥱")
                    ui.label("😐")
                    ui.label("😲")
                    ui.label("🫨")

                with ui.column().classes('items-center w-full'):
                    energy_slider = ui.slider(min=1, max=5, value=5).classes("w-full")
                    ui.label().bind_text_from(energy_slider, 'value').classes("text-xl font-bold mt-4 text-center")

            with ui.card().classes("w-full items-center"):
                ui.label("Why do you feel this way today?").classes("text-xl font-bold mb-4")
                textarea = ui.textarea(placeholder="Write your notes here...").classes("w-full mb-4").props("outlined autogrow rows=4")

                # Listener to get weather data from JS
                weather_desc: Optional[str] = None
                async def receive_weather_data(desc: str):
                    nonlocal weather_desc
                    weather_desc = desc
                ui.on('weather_data', receive_weather_data)

                # Method to submit notes
                async def submit_notes():
                    if not textarea.value.strip():
                        ui.notify("Please write something before submitting.", color="red")
                    elif weather_desc is None:
                        ui.notify("Weather data is still loading. Please wait.", color="red")
                    else:
                        ui.notify("Note Submitted!", color="green")

                        async def get_weather_summary(desc: str) -> str:
                            '''
                            Parses weather_data to extract a brief weather summary.

                            Example: broken clouds -> cloudy

                            Mapping:
                            "clear", "sun" -> "sunny"
                            "cloud", "overcast" -> "cloudy"
                            "shower", "rain" -> "rainy"
                            "storm", "thunder" -> "stormy"
                            "snow" -> "snowy"
                            "fog", "mist" -> "foggy"
                            '''

                            # desc is currently GenericEventArguments, need to extract string
                            desc = str(desc).lower()

                            if "clear" in desc or "sun" in desc:
                                return "sunny"
                            if "cloud" in desc or "overcast" in desc:
                                return "cloudy"
                            if "shower" in desc or "rain" in desc:
                                return "rainy"
                            if "storm" in desc or "thunder" in desc:
                                return "stormy"
                            if "snow" in desc:
                                return "snowy"
                            if "fog" in desc or "mist" in desc:
                                return "foggy"
                            return desc
                        
                        await mood_log_repo.create_mood_log(
                            user_id=user.id,
                            mood_value=mood_slider.value,
                            energy_level=energy_slider.value,
                            notes=textarea.value,
                            weather=await get_weather_summary(weather_desc)
                        )

                # Method to edit notes if already submitted today
                async def edit_notes():
                    if not textarea.value.strip():
                        ui.notify("Please write something before submitting.", color="red")
                    else:
                        ui.notify("Note Edited!", color="green")

                        await mood_log_repo.edit_latest_mood_log(
                            user_id=user.id,
                            mood_value=mood_slider.value,
                            energy_level=energy_slider.value,
                            notes=textarea.value
                        )

            with ui.column().classes("w-full items-center mt-6"):
                if datetime.utcnow().date() == (await mood_log_repo.get_most_recent_log_date(user.id)).date():
                    ui.button("Edit!", on_click=edit_notes).classes("bg-blue-500 text-white px-6 py-3 rounded-lg shadow hover:bg-blue-600")
                else:
                    ui.button("Submit!", on_click=submit_notes).classes("bg-blue-500 text-white px-6 py-3 rounded-lg shadow hover:bg-blue-600")

        # Music
        with ui.card().classes("basis-1/4 p-6 shadow rounded-2xl h-full border items-center"):
            ui.label("Music Sessions").classes("text-xl font-bold mb-4 text-center")
            ui.label("Focus Music").classes("text-lg mb-4")
            ui.icon("play_circle").classes("text-5xl text-blue-500 mb-3")
            ui.button("1-Min Refresher").classes("w-full mb-2 bg-blue-500 text-white")
            ui.button("3-Min Calm Down").classes("w-full bg-blue-500 text-white")

        # Daily Tip + Weather
        with ui.card().classes("flex-1 p-6 shadow rounded-2xl h-full border items-center"):
            ui.label("Daily Summary").classes("text-xl font-bold mb-4 text-center")

            with ui.column().classes("items-center mb-4"):
                weather_icon = ui.label("🌍").props("id=weather-icon") \
                .classes("text-6xl mb-2")
                weather_label = ui.label("Loading weather...") \
                .classes("text-gray-600") \
                .props("id=weather-text")

            with ui.column().classes("bg-yellow-50 rounded-xl border p-4"):
                weather_stats = await mood_log_repo.get_weather_mood_stats(user.id)
                
                def get_max_mood_weather(weather_stats):
                    if not weather_stats:
                        return "no data available yet."
                    
                    max_entry = max(weather_stats, key=lambda x: x["avg_mood"])
                    return max_entry["weather"]

                ui.label("Daily Tip").classes("font-semibold mb-1")
                ui.label(f"You feel the most happy when it is {get_max_mood_weather(weather_stats)}").classes("text-gray-700")
    
    # Weather 
    await ui.run_javascript('''

        setTimeout(() => {

                            
            function get_emoji(desc) {
                desc = desc.toLowerCase();

                if (desc.includes("clear")) return "☀️";
                if (desc.includes("sun")) return "☀️";    
                if (desc.includes("cloud")) return "☁️";            
                if (desc.includes("overcast")) return "☁️";            
                if (desc.includes("shower")) return "🌧️";           
                if (desc.includes("rain")) return "🌧️";            
                if (desc.includes("storm")) return "⛈️";
                if (desc.includes("thunder")) return "⛈️";
                if (desc.includes("snow")) return "🌨️";
                if (desc.includes("clear")) return "☀️";
                if (desc.includes("fog")) return "🌫️";
                if (desc.includes("mist")) return "🌫️";
                            
                return "🌍";
            }
            

            const label = document.getElementById('weather-text');
            const icon = document.getElementById('weather-icon');
                            
            if (!label || !icon ) {
                console.log("NO WEATHER LABEL FOUND");
                return;
            }

            if (!navigator.geolocation) {
                label.innerText = 'Geolocation not supported';
                return;
            }

            navigator.geolocation.getCurrentPosition(async function(pos) {

                const lat = pos.coords.latitude;
                const lon = pos.coords.longitude;

                console.log("Got location:", lat, lon);  // <-- debugging

                const resp = await fetch(`/weather?lat=${lat}&lon=${lon}`);  //sends coordinates to backend (weather.py)
                const data = await resp.json();

                const desc = (data.weather?.[0]?.description) || 'Unknown';
                const temp = data.main?.temp ? Math.round(data.main.temp) : null;
                            
                icon.innerText = get_emoji(desc);

                if (temp !== null) {
                    label.innerText = `${temp}°C – ${desc}`;
                } else {
                    label.innerText = desc;
                }
                            
                // Send weather description back to Python
                emitEvent('weather_data', desc);

            }, function(err) {
                label.innerText = 'Location denied';
            }, {
                enableHighAccuracy: true,
                maximumAge: 0,
                timeout: 5000
            });

        }, 300);  // <-- 300ms delay FIXES NiceGUI timing issues
    ''')

@ui.page("/users/{username}/journal")
async def user_journal_page(username: str, user_repo: UserRepositoryV2 = Depends(get_user_repository_v2), mood_log_repo = Depends(get_mood_log_repository_v2)):

    # Verify user is authenticated and accessing their own page
    authenticated_user = await require_auth(username)
    if not authenticated_user:
        return
    
    user = await user_repo.get_by_name(username)
    if not user: 
        ui.label("User not found.")
        return
    
    # Navbar with logout
    with ui.header().classes('justify-between items-center px-4 py-6 hover:shadow-lg transition-all duration-200'):
        ui.label('Mindfuly - Your Daily Wellness Tracker').classes('text-2xl font-bold')
        with ui.row().classes("gap-15 items-center"):
            ui.link("Overview", f"/users/{username}/home").classes("text-white text-lg no-underline")
            ui.link("Journal", f"/users/{username}/journal").classes("text-white text-lg no-underline")
            ui.link("My Analytics", f"/users/{username}/analytics").classes("text-white text-lg no-underline")
            ui.link("Settings", f"/users/{username}/settings").classes("text-white text-lg no-underline")
            ui.button('Logout', on_click=lambda: handle_logout(), icon='logout').classes('bg-red-500 ml-4')

    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.notify('Logged out successfully', color='green')
        ui.navigate.to('/home')

    with ui.column().classes('w-full items-center mt-10 mb-8'):
        ui.label(f"{username}'s Journal").classes('text-4xl font-bold text-center mb-1')

    mood_logs = await mood_log_repo.get_mood_logs(user.id, limit=20)

    # Placeholder for journal entries
    with ui.column().classes('w-full max-w-4xl mx-auto'):
        if not mood_logs:
            ui.label("No journal entries found. Start logging your mood today!").classes("text-gray-600 italic")
        for log in mood_logs:
            with ui.card().classes("w-full mb-4 p-4 shadow rounded-lg border"):
                with ui.row().classes("justify-between items-center mb-2"):
                    ui.label(f"Mood: {log.mood_value}").classes("font-semibold")
                    ui.label(f"Energy: {log.energy_level}").classes("font-semibold")
                    ui.label(f"Created on: {log.created_at.date()}").classes("text-gray-500 text-sm")
                ui.label(log.notes).classes("mt-2")

@ui.page("/users/{username}/analytics")
async def user_analytics_page(username: str, user_repo: UserRepositoryV2 = Depends(get_user_repository_v2), mood_log_repo = Depends(get_mood_log_repository_v2)):

    # Verify user is authenticated and accessing their own page
    authenticated_user = await require_auth(username)
    if not authenticated_user:
        return
    
    user = await user_repo.get_by_name(username)
    if not user: 
        ui.label("User not found.")
        return
    
    # Navbar with logout
    with ui.header().classes('justify-between items-center px-4 py-6 hover:shadow-lg transition-all duration-200'):
        ui.label('Mindfuly - Your Daily Wellness Tracker').classes('text-2xl font-bold')
        with ui.row().classes("gap-15 items-center"):
            ui.link("Overview", f"/users/{username}/home").classes("text-white text-lg no-underline")
            ui.link("Journal", f"/users/{username}/journal").classes("text-white text-lg no-underline")
            ui.link("My Analytics", f"/users/{username}/analytics").classes("text-white text-lg no-underline")
            ui.link("Settings", f"/users/{username}/settings").classes("text-white text-lg no-underline")
            ui.button('Logout', on_click=lambda: handle_logout(), icon='logout').classes('bg-red-500 ml-4')

    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.notify('Logged out successfully', color='green')
        ui.navigate.to('/home')

    with ui.column().classes('w-full items-center mt-10 mb-8'):
        ui.label(f"{username}'s Analytics").classes('text-4xl font-bold text-center mb-1')

    # Fetch running means data
    running_means = await mood_log_repo.get_running_means(user.id, limit=20)
    mood_logs = await mood_log_repo.get_mood_logs(user.id, limit=20)

    # Create double line chart for running means
    if not mood_logs:
        ui.label("Not enough data to display analytics. Start logging your mood today!").classes("text-gray-600 italic")
    else:
        dates = [entry["date"] for entry in running_means][::-1]
        mood_values = [entry["avg_mood"] for entry in running_means][::-1]
        energy_values = [entry["avg_energy"] for entry in running_means][::-1]

        with ui.card().classes("w-full max-w-4xl p-4 shadow rounded-lg border text-center mx-auto mt-6"):
            with ui.row().classes("justify-center w-full"):
                ui.label("Your Mood and Energy").classes("text-xl font-bold mb-4 text-center")
            
            # Graph all moods and energy levels as a scatter plot
            ui.echart({
                "tooltip": {
                    "trigger": "axis"
                },
                "legend": {
                    "data": ["Mood Logs", "Energy Logs"]
                },
                "xAxis": {
                    "type": "category",
                    "data": [log.created_at.date().isoformat() for log in mood_logs][::-1]
                },
                "yAxis": {
                    "type": "value",
                    "min": 1,
                    "max": 5
                },
                "series": [
                    {
                        "name": "Mood Logs",
                        "type": "scatter",
                        "data": [log.mood_value for log in mood_logs][::-1],
                        "itemStyle": {
                            "color": "#42A5F5"
                        }
                    },
                    {
                        "name": "Energy Logs",
                        "type": "scatter",
                        "data": [log.energy_level for log in mood_logs][::-1],
                        "itemStyle": {
                            "color": "#66BB6A"
                        }
                    }
                ]
            })

        with ui.card().classes("w-full max-w-4xl p-4 shadow rounded-lg border text-center mx-auto"):
            with ui.row().classes("justify-center w-full"):
                ui.label("Average Mood and Energy Levels Over Time").classes("text-xl font-bold mb-4 text-center")

            # Create a double line chart using NiceGUI's echart
            ui.echart({
                "tooltip": {
                    "trigger": "axis"
                },
                "legend": {
                    "data": ["Running Mean Mood", "Running Mean Energy"]
                },
                "xAxis": {
                    "type": "category",
                    "data": dates
                },
                "yAxis": {
                    "type": "value",
                    "min": 1,
                    "max": 5
                },
                "series": [
                    {
                        "name": "Average Mood",
                        "type": "line",
                        "data": mood_values,
                        "smooth": True,
                        "lineStyle": {
                            "color": "#42A5F5"
                        }
                    },
                    {
                        "name": "Average Energy",
                        "type": "line",
                        "data": energy_values,
                        "smooth": True,
                        "lineStyle": {
                            "color": "#66BB6A"
                        }
                    }
                ]
            })

@ui.page("/users/{username}/settings")
async def users_settings_page(username: str, user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)):

    # Verify user is authenticated and accessing their own page
    authenticated_user = await require_auth(username)
    if not authenticated_user:
        return
    
    user = await user_repo.get_by_name(username)
    if not user: 
        ui.label("User not found.")
        return
    
    # Navbar with logout
    with ui.header().classes('justify-between items-center px-4 py-6 hover:shadow-lg transition-all duration-200'):
        ui.label('Mindfuly - Your Daily Wellness Tracker').classes('text-2xl font-bold')
        with ui.row().classes("gap-15 items-center"):
            ui.link("Overview", f"/users/{username}/home").classes("text-white text-lg no-underline")
            ui.link("Journal", f"/users/{username}/journal").classes("text-white text-lg no-underline")
            ui.link("My Analytics", f"/users/{username}/analytics").classes("text-white text-lg no-underline")
            ui.link("Settings", f"/users/{username}/settings").classes("text-white text-lg no-underline")
            ui.button('Logout', on_click=lambda: handle_logout(), icon='logout').classes('bg-red-500 ml-4')

    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.notify('Logged out successfully', color='green')
        ui.navigate.to('/home')

    with ui.column().classes("w-full items-center mt-10"):
        ui.label("User Settings").classes("text-3xl font-bold mb-6")

        with ui.row().classes("w-full justify-center gap-10"):
    
            with ui.card().classes("w-full max-w-3xl p-8 shadow-md rounded-2xl border"):
                ui.label("Account Information").classes("text-xl font-bold mb-4")
                
                with ui.column().classes("w-full p-4 mb-6 border border-gray-300/40 rounded-xl bg-gray-50/30"):
                    ui.label(f"Username: {user.name}").classes("mb-2")
                    ui.label(f"Email: {user.email}").classes("mb-4")

                ui.label("Update Information").classes("text-xl font-bold mb-4")
                name_input = ui.input("Display name", value=user.name).classes("mb-3 w-full")
                email_input = ui.input("Email", value=user.email).classes("mb-3 w-full")
                ui.button("Save changes", on_click=lambda: ui.notify("Not wired yet"))
        
    
            with ui.column().classes("basis-1/2"):
                with ui.card().classes("w-full p-8 border shadow rounded-2xl"):
                    ui.label("Danger Zone").classes("text-xl font-bold mb-4 text-red-500")
                    ui.button("Delete Account")