from fastapi import Depends, HTTPException
from nicegui import ui
import logging
import asyncio
from datetime import timedelta
from typing import Optional

from src.mindfuly.routes.users import create_user
from user_service_v2.models.user import UserSchema, get_user_repository_v2, UserRepositoryV2
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
    # Add custom CSS for beautiful gradients and animations
    ui.add_head_html('''
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
            * { font-family: 'Inter', sans-serif; }
            .gradient-bg {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .glass-card {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            }
            .hero-title {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .feature-card {
                transition: all 0.3s ease;
            }
            .feature-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            }
            .btn-primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                transition: all 0.3s ease;
            }
            .btn-primary:hover {
                transform: scale(1.05);
                box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
            }
            .btn-secondary {
                background: white;
                color: #667eea;
                border: 2px solid #667eea;
                transition: all 0.3s ease;
            }
            .btn-secondary:hover {
                background: #667eea;
                color: white;
                transform: scale(1.05);
            }
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            .fade-in-up {
                animation: fadeInUp 0.6s ease-out;
            }
        </style>
    ''')
    
    with ui.column().classes('gradient-bg w-full min-h-screen items-center justify-center p-8'):
        with ui.column().classes('max-w-6xl w-full items-center fade-in-up'):
            with ui.column().classes('items-center mb-8'):
                ui.label('💭').classes('text-8xl mb-4')
                ui.label('Mindfuly').classes('hero-title text-7xl font-extrabold mb-4')
                ui.label('Your Personal Wellness & Mindfulness Companion').classes('text-2xl text-white font-light mb-12 text-center')
            
            with ui.row().classes('w-full justify-center gap-6 mb-12 flex-wrap'):
                with ui.card().classes('feature-card glass-card p-8 max-w-xs'):
                    ui.label('📊').classes('text-5xl mb-4 text-center')
                    ui.label('Track Your Mood').classes('text-2xl font-bold mb-3 text-center text-gray-800')
                    ui.label('Log your daily emotions and track patterns over time').classes('text-gray-600 text-center')
                
                with ui.card().classes('feature-card glass-card p-8 max-w-xs'):
                    ui.label('🎵').classes('text-5xl mb-4 text-center')
                    ui.label('Mood-Based Music').classes('text-2xl font-bold mb-3 text-center text-gray-800')
                    ui.label('Discover music that matches your current emotional state').classes('text-gray-600 text-center')
                
                with ui.card().classes('feature-card glass-card p-8 max-w-xs'):
                    ui.label('🌤️').classes('text-5xl mb-4 text-center')
                    ui.label('Weather Insights').classes('text-2xl font-bold mb-3 text-center text-gray-800')
                    ui.label('Understand how weather affects your mood and wellbeing').classes('text-gray-600 text-center')
            
            with ui.row().classes('gap-6 mt-8'):
                ui.button('🚀 Get Started', on_click=lambda: ui.navigate.to('/signup')).classes('btn-primary text-white px-12 py-4 text-lg font-semibold rounded-full')
                ui.button('🔐 Sign In', on_click=lambda: ui.navigate.to('/login')).classes('btn-secondary px-12 py-4 text-lg font-semibold rounded-full')


@ui.page("/login")
async def login_page(user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)):
    ui.add_head_html('''
        <style>
            .login-gradient {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .login-card {
                background: rgba(255, 255, 255, 0.98);
                backdrop-filter: blur(10px);
                border-radius: 24px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            }
            .input-field {
                border-radius: 12px;
                border: 2px solid #e5e7eb;
                transition: all 0.3s ease;
            }
            .input-field:focus {
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
        </style>
    ''')
    
    with ui.column().classes('login-gradient w-full min-h-screen items-center justify-center p-8'):
        with ui.card().classes('login-card p-12 max-w-md w-full fade-in-up'):
            with ui.column().classes('items-center mb-8 w-full text-center'):
                ui.label('💭').classes('text-6xl mb-4')
                ui.label('Welcome Back').classes('text-4xl font-bold text-gray-800 mb-2 text-center w-full')
                ui.label('Sign in to continue your wellness journey').classes('text-gray-600 text-center text-center w-full')
            
            with ui.column().classes('w-full gap-4'):
                username_input = ui.input('Username', placeholder='Enter your username').classes('input-field w-full')
                password_input = ui.input('Password', password=True, placeholder='Enter your password').classes('input-field w-full')
                
                error_label = ui.label().classes('text-red-500 text-sm mt-2')
            error_label.visible = False

            async def handle_login():
                if not username_input.value or not password_input.value:
                    error_label.text = "Please fill in all fields."
                    error_label.visible = True
                    return
                
                user = await user_repo.get_by_name(username_input.value)

                if user == None:
                    error_label.text = "User not found. Please check your username."
                    error_label.visible = True
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
                    
                    ui.notify('Login successful!', color='green', icon='check_circle')
                    ui.navigate.to(f"/users/{username_input.value}/home")
                    
                else:
                    error_label.text = "Invalid password. Please try again."
                    error_label.visible = True
                    password_input.value = ""
                    password_input.focus()

                    ui.button('🔐 Sign In', on_click=handle_login).classes('btn-primary text-white w-full py-4 text-lg font-semibold rounded-xl mt-4')
            password_input.on('keydown.enter', handle_login)
            
            # Footer
            with ui.row().classes('w-full justify-center items-center mt-6 gap-2'):
                ui.label('New to Mindfuly?').classes('text-gray-600')
                ui.link('Create an account', '/signup').classes('text-purple-600 font-semibold hover:underline')
            
            with ui.row().classes('w-full justify-center mt-4'):
                ui.link('← Back to Home', '/home').classes('text-gray-500 hover:text-purple-600 text-sm')


@ui.page("/signup")
async def signup_page(user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)):
    ui.add_head_html('''
        <style>
            .signup-gradient {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .signup-card {
                background: rgba(255, 255, 255, 0.98);
                backdrop-filter: blur(10px);
                border-radius: 24px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            }
            .input-field {
                border-radius: 12px;
                border: 2px solid #e5e7eb;
                transition: all 0.3s ease;
            }
            .input-field:focus {
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
        </style>
    ''')
    
    with ui.column().classes('signup-gradient w-full min-h-screen items-center justify-center p-8'):
        with ui.card().classes('signup-card p-12 max-w-md w-full fade-in-up'):
            with ui.column().classes('items-center mb-8 w-full'):
                ui.label('💭').classes('text-6xl mb-4')
                ui.label('Join Mindfuly').classes('text-4xl font-bold text-gray-800 mb-2 text-center w-full')
                ui.label('Start your wellness journey today').classes('text-gray-600 text-center w-full')
            
            with ui.column().classes('w-full gap-4'):
                username_input = ui.input('Username', placeholder='Choose a username').classes('input-field w-full')
                email_input = ui.input('Email', placeholder='Enter your email').classes('input-field w-full')
                password_input = ui.input('Password', password=True, placeholder='Create a password').classes('input-field w-full')
                
                error_label = ui.label().classes('text-red-500 text-sm mt-2')
                error_label.visible = False
            
            async def handle_signup():
                if not username_input.value or not email_input.value or not password_input.value:
                    error_label.text = "Please fill in all fields."
                    error_label.visible = True
                    return
                
                # Basic email validation
                if '@' not in email_input.value:
                    error_label.text = "Please enter a valid email address."
                    error_label.visible = True
                    return
                
                if len(password_input.value) < 6:
                    error_label.text = "Password must be at least 6 characters."
                    error_label.visible = True
                    return

                result = await user_repo.create(username_input.value, email_input.value, password_input.value, tier=1)
                if not result:
                    error_label.text = "Username or email already exists. Please try again."
                    error_label.visible = True
                    return
                
                ui.notify('Account created successfully! Redirecting to login...', color='green', icon='check_circle')
                await ui.run_javascript('setTimeout(() => {}, 1000)')
                ui.navigate.to('/login')

            ui.button('✨ Create Account', on_click=handle_signup).classes('btn-primary text-white w-full py-4 text-lg font-semibold rounded-xl mt-4')
            password_input.on('keydown.enter', handle_signup)
            
            with ui.row().classes('w-full justify-center items-center mt-6 gap-2'):
                ui.label('Already have an account?').classes('text-gray-600')
                ui.link('Sign in', '/login').classes('text-purple-600 font-semibold hover:underline')
            
            with ui.row().classes('w-full justify-center mt-4'):
                ui.link('← Back to Home', '/home').classes('text-gray-500 hover:text-purple-600 text-sm')


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
async def user_home_screen(username: str, user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)):
    # Verify user is authenticated and accessing their own page
    authenticated_user = await require_auth(username)
    if not authenticated_user:
        return
    
    user = await user_repo.get_by_name(username)
    if not user: 
        ui.label("User not found.")
        return
    
    # Add custom styles for dashboard
    ui.add_head_html('''
        <style>
            body {
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
            }
            .dashboard-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            }
            .nav-link {
                transition: all 0.3s ease;
                padding: 8px 16px;
                border-radius: 8px;
            }
            .nav-link:hover {
                background: rgba(255, 255, 255, 0.1);
            }
            .welcome-card {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 20px;
                box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
            }
            .dashboard-card {
                transition: all 0.3s ease;
                border-radius: 16px;
                background: white;
            }
            .dashboard-card:hover {
                transform: translateY(-4px);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
            }
        </style>
    ''')
    
    with ui.header().classes('dashboard-header justify-between items-center px-8 py-4'):
        with ui.row().classes('items-center gap-2'):
            ui.label('💭').classes('text-3xl')
            ui.label('Mindfuly').classes('text-2xl font-bold text-white')
        with ui.row().classes("gap-6 items-center"):
            ui.link("Overview", f"/users/{username}/home").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Journal", f"/users/{username}/journal").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Analytics", f"/users/{username}/analytics").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Settings", f"/users/{username}/settings").classes("nav-link text-white text-base font-medium no-underline")
            ui.button('🚪 Logout', on_click=lambda: handle_logout()).classes('bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg font-medium')

    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.notify('Logged out successfully', color='green', icon='check_circle')
        ui.navigate.to('/home')

    # Welcome Section
    with ui.column().classes('w-full items-center mt-8 mb-10 px-4 text-center'):
        with ui.card().classes('welcome-card p-8 max-w-4xl w-full text-center'):
            with ui.row().classes('items-center justify-between w-full'):
                with ui.column().classes('flex-1'):
                    ui.label(f"Welcome back, {username}! 👋").classes('text-4xl font-bold text-white mb-2 text-center')
                    ui.label("Track your mood, discover music, and stay mindful").classes('text-xl text-white opacity-90')
                ui.label('💭').classes('text-8xl opacity-20')

    with ui.row().classes("w-full max-w-7xl justify-center gap-8 mx-auto items-stretch px-4 mb-8"):
        # Mood Log
        with ui.card().classes("dashboard-card basis-1/2 p-8 shadow-lg rounded-2xl border-0 bg-white items-center h-full"):
            ui.label("Today's Mood Log").classes("text-3xl font-bold mb-2 text-center text-gray-800")
            ui.label("Adjust the slider based on your mood!").classes("text-base text-gray-600 font-medium mb-8 text-center")
            
            with ui.row().classes("justify-center gap-25 mb-3 text-2xl"):
                ui.label("😞")
                ui.label("🙁")
                ui.label("😐")
                ui.label("🙂")
                ui.label("😄")

            with ui.column().classes('items-center w-full'):
                slider = ui.slider(min=1, max=5, value=5).classes("w-full")
                ui.label().bind_text_from(slider, 'value').classes("text-xl font-bold mt-4 text-center")

            with ui.column().classes("w-full items-center mt-6"):
                ui.button("Submit!", on_click=lambda: ui.notify("Mood submitted!")).classes("bg-blue-500 text-white px-6 py-3 rounded-lg shadow hover:bg-blue-600")

        # Music - YouTube Integration (Mood-Based)
        with ui.card().classes("dashboard-card basis-1/4 p-6 shadow-lg rounded-2xl h-full border-0 bg-white"):
            ui.label("Mood Music Player").classes("text-2xl font-bold mb-4 text-center text-gray-800")
            
            # Mood Selection
            ui.label("Select Your Mood").classes("text-sm font-semibold text-gray-600 mb-2 text-center")
            with ui.row().classes("justify-center gap-2 mb-3 flex-wrap"):
                ui.button("😞 Sad", on_click=None).props("id=mood-sad").classes("mood-btn bg-blue-100 hover:bg-blue-200 text-blue-800 px-3 py-2 text-sm")
                ui.button("🙁 Calm", on_click=None).props("id=mood-calm").classes("mood-btn bg-teal-100 hover:bg-teal-200 text-teal-800 px-3 py-2 text-sm")
                ui.button("😐 Peaceful", on_click=None).props("id=mood-peaceful").classes("mood-btn bg-green-100 hover:bg-green-200 text-green-800 px-3 py-2 text-sm")
                ui.button("🙂 Happy", on_click=None).props("id=mood-happy").classes("mood-btn bg-yellow-100 hover:bg-yellow-200 text-yellow-800 px-3 py-2 text-sm")
                ui.button("😄 Energetic", on_click=None).props("id=mood-energetic").classes("mood-btn bg-orange-100 hover:bg-orange-200 text-orange-800 px-3 py-2 text-sm")
            
            # Selected mood display
            ui.label("Current: Calm 🙁").props("id=selected-mood-display").classes("text-xs text-center text-gray-500 mb-3")
            
            # Focus Timer
            ui.label("Focus Timer").classes("text-sm font-semibold text-gray-600 mb-2 text-center")
            with ui.row().classes("justify-center gap-2 mb-3"):
                ui.button("1 min", on_click=None).props("id=timer-1min").classes("timer-btn bg-purple-100 hover:bg-purple-200 text-purple-800 px-3 py-1 text-xs")
                ui.button("3 min", on_click=None).props("id=timer-3min").classes("timer-btn bg-purple-100 hover:bg-purple-200 text-purple-800 px-3 py-1 text-xs")
                ui.button("Off", on_click=None).props("id=timer-off").classes("timer-btn bg-gray-100 hover:bg-gray-200 text-gray-800 px-3 py-1 text-xs")
            ui.label("Timer: Off").props("id=timer-display").classes("text-xs text-center text-gray-500 mb-3")
            
            # YouTube player container
            ui.html("<div id='youtube-player-container' style='display: none;'></div>", sanitize=False)
            
            # Currently playing info
            with ui.column().props("id=current-video-info").classes("w-full mb-3").style("display: none;"):
                ui.label("Now Playing").classes("text-sm font-semibold text-gray-600 mb-2 text-center")
                ui.label("").props("id=current-video-title").classes("text-sm font-semibold text-center")
                ui.label("").props("id=current-video-channel").classes("text-xs text-gray-600 text-center")
            
            # Playback controls
            with ui.row().props("id=youtube-controls").classes("w-full justify-center gap-2 mb-3").style("display: none;"):
                ui.button(icon="skip_previous").props("id=yt-prev-btn").classes("bg-red-500 text-white")
                ui.button(icon="skip_next").props("id=yt-next-btn").classes("bg-red-500 text-white")
            
            # Queue info
            with ui.column().props("id=youtube-queue-section").classes("w-full").style("display: none;"):
                ui.label("Up Next").classes("text-sm font-semibold mb-2")
                ui.html("<div id='yt-queue-list' class='text-xs text-gray-600'></div>", sanitize=False)

        # Daily Tip + Weather
        with ui.card().classes("dashboard-card flex-1 p-6 shadow-lg rounded-2xl h-full border-0 bg-white items-center"):
            ui.label("Daily Summary").classes("text-2xl font-bold mb-4 text-center text-gray-800")

            with ui.column().classes("items-center mb-4"):
                weather_icon = ui.label("🌍").props("id=weather-icon") \
                .classes("text-6xl mb-2")
                weather_label = ui.label("Loading weather...") \
                .classes("text-gray-600") \
                .props("id=weather-text")

            with ui.column().classes("bg-yellow-50 rounded-xl border p-4"):
                ui.label("Daily Tip").classes("font-semibold mb-1")
                ui.label("You feel happy on a certain day... (example)").classes("text-gray-700")

    # Notes
    with ui.card().classes("w-full max-w-7xl mx-auto mt-10 p-6 shadow rounded-2xl items-center border"):
        ui.label("What's on your mind today?").classes("text-xl font-bold mb-4")
        textarea = ui.textarea(placeholder="Write your notes here...").classes("w-full mb-4").props("outlined autogrow rows=4")
        ui.button("SAVE NOTES", on_click=lambda: ui.notify("Note Submitted!")).classes("bg-blue-500 text-white w-full py-2 rounded-lg")

    
    
    
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

            }, function(err) {
                label.innerText = 'Location denied';
            }, {
                enableHighAccuracy: true,
                maximumAge: 0,
                timeout: 5000
            });

        }, 300);
    ''')
    await ui.run_javascript(f'''
        // Load YouTube IFrame API
        if (!window.YT) {{
            const tag = document.createElement('script');
            tag.src = 'https://www.youtube.com/iframe_api';
            const firstScriptTag = document.getElementsByTagName('script')[0];
            firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);
        }}
        
        setTimeout(() => {{
            const username = '{username}';
            let player = null;
            let videoQueue = [];
            let currentVideoIndex = 0;
            let currentMood = 'calm';
            let focusTimer = null;
            let timerDuration = 0; // 0 = off, 1 = 1min, 3 = 3min
            let timerStartTime = null;
            
            // Get DOM elements
            const youtubePlayerContainer = document.getElementById('youtube-player-container');
            const currentVideoInfo = document.getElementById('current-video-info');
            const currentVideoTitle = document.getElementById('current-video-title');
            const currentVideoChannel = document.getElementById('current-video-channel');
            const youtubeControls = document.getElementById('youtube-controls');
            const ytPrevBtn = document.getElementById('yt-prev-btn');
            const ytNextBtn = document.getElementById('yt-next-btn');
            const youtubeQueueSection = document.getElementById('youtube-queue-section');
            const ytQueueList = document.getElementById('yt-queue-list');
            const selectedMoodDisplay = document.getElementById('selected-mood-display');
            const timerDisplay = document.getElementById('timer-display');
            
            // Get mood buttons
            const moodSadBtn = document.getElementById('mood-sad');
            const moodCalmBtn = document.getElementById('mood-calm');
            const moodPeacefulBtn = document.getElementById('mood-peaceful');
            const moodHappyBtn = document.getElementById('mood-happy');
            const moodEnergeticBtn = document.getElementById('mood-energetic');
            
            // Get timer buttons
            const timer1minBtn = document.getElementById('timer-1min');
            const timer3minBtn = document.getElementById('timer-3min');
            const timerOffBtn = document.getElementById('timer-off');
            
            const moodButtons = {{
                'sad': {{ btn: moodSadBtn, emoji: '😞', label: 'Sad' }},
                'calm': {{ btn: moodCalmBtn, emoji: '🙁', label: 'Calm' }},
                'peaceful': {{ btn: moodPeacefulBtn, emoji: '😐', label: 'Peaceful' }},
                'happy': {{ btn: moodHappyBtn, emoji: '🙂', label: 'Happy' }},
                'energetic': {{ btn: moodEnergeticBtn, emoji: '😄', label: 'Energetic' }}
            }};
            
            const timerButtons = {{
                0: timerOffBtn,
                1: timer1minBtn,
                3: timer3minBtn
            }};
            
            // Update mood selection
            function selectMood(mood) {{
                currentMood = mood;
                
                // Update selected mood display
                const moodInfo = moodButtons[mood];
                selectedMoodDisplay.innerText = `Current: ${{moodInfo.label}} ${{moodInfo.emoji}}`;
                
                // Update button styles - highlight selected
                Object.keys(moodButtons).forEach(key => {{
                    const btn = moodButtons[key].btn;
                    if (key === mood) {{
                        btn.classList.add('ring-2', 'ring-offset-2', 'ring-purple-500', 'font-bold');
                    }} else {{
                        btn.classList.remove('ring-2', 'ring-offset-2', 'ring-purple-500', 'font-bold');
                    }}
                }});
                
                // Automatically load music for the selected mood
                loadMoodMusic();
            }}
            
            // Set up mood button click handlers
            Object.keys(moodButtons).forEach(mood => {{
                const btn = moodButtons[mood].btn;
                if (btn) {{
                    btn.addEventListener('click', () => selectMood(mood));
                }}
            }});
            
            // Timer functions
            function setTimer(minutes) {{
                timerDuration = minutes;
                
                // Clear existing timer
                if (focusTimer) {{
                    clearTimeout(focusTimer);
                    focusTimer = null;
                }}
                
                // Update timer button styles
                Object.keys(timerButtons).forEach(min => {{
                    const btn = timerButtons[min];
                    if (btn) {{
                        if (parseInt(min) === minutes) {{
                            btn.classList.add('ring-2', 'ring-offset-2', 'ring-blue-500', 'font-bold');
                        }} else {{
                            btn.classList.remove('ring-2', 'ring-offset-2', 'ring-blue-500', 'font-bold');
                        }}
                    }}
                }});
                
                if (minutes === 0) {{
                    timerDisplay.innerText = 'Timer: Off';
                    timerStartTime = null;
                }} else {{
                    timerDisplay.innerText = `Timer: ${{minutes}} min`;
                    timerStartTime = Date.now();
                    
                    // Set timer
                    focusTimer = setTimeout(() => {{
                        // Stop music
                        if (player && player.pauseVideo) {{
                            player.pauseVideo();
                        }}
                        
                        // Show focus reminder
                        alert('⏰ Time to focus! Take a moment to center yourself and concentrate on your tasks.');
                        
                        timerDisplay.innerText = 'Timer: Expired';
                    }}, minutes * 60 * 1000);
                }}
            }}
            
            // Update timer display periodically
            function updateTimerDisplay() {{
                if (timerDuration > 0 && timerStartTime) {{
                    const elapsed = Date.now() - timerStartTime;
                    const remaining = (timerDuration * 60 * 1000) - elapsed;
                    
                    if (remaining > 0) {{
                        const minutes = Math.floor(remaining / 60000);
                        const seconds = Math.floor((remaining % 60000) / 1000);
                        timerDisplay.innerText = `Timer: ${{minutes}}:${{seconds.toString().padStart(2, '0')}}`;
                    }}
                }}
            }}
            
            // Update timer display every second
            setInterval(updateTimerDisplay, 1000);
            
            // Set up timer button click handlers
            if (timer1minBtn) {{
                timer1minBtn.addEventListener('click', () => setTimer(1));
            }}
            if (timer3minBtn) {{
                timer3minBtn.addEventListener('click', () => setTimer(3));
            }}
            if (timerOffBtn) {{
                timerOffBtn.addEventListener('click', () => setTimer(0));
            }}
            
            // Initialize YouTube Player
            function onYouTubeIframeAPIReady() {{
                console.log('YouTube API Ready');
            }}
            
            // Create YouTube player
            function initializeYouTubePlayer(videoId) {{
                if (player) {{
                    player.loadVideoById(videoId);
                    return;
                }}
                
                youtubePlayerContainer.innerHTML = '<div id="youtube-player"></div>';
                youtubePlayerContainer.style.display = 'block';
                
                player = new YT.Player('youtube-player', {{
                    height: '200',
                    width: '100%',
                    videoId: videoId,
                    playerVars: {{
                        'autoplay': 1,
                        'controls': 1,
                        'modestbranding': 1,
                        'rel': 0
                    }},
                    events: {{
                        'onStateChange': onPlayerStateChange,
                        'onError': onPlayerError
                    }}
                }});
            }}
            
            // Handle player state changes
            function onPlayerStateChange(event) {{
                if (event.data === YT.PlayerState.ENDED) {{
                    playNext();
                }}
            }}
            
            // Handle player errors (unavailable videos, etc.)
            function onPlayerError(event) {{
                console.error('YouTube player error:', event.data);
                let errorMessage = 'Video error';
                
                // Error codes: 2 = invalid param, 5 = HTML5 error, 100 = not found, 101/150 = not embeddable
                if (event.data === 100) {{
                    errorMessage = 'Video not found';
                }} else if (event.data === 101 || event.data === 150) {{
                    errorMessage = 'Video not available for playback';
                }} else {{
                    errorMessage = 'Video playback error';
                }}
                
                console.log(`${{errorMessage}}, skipping to next video...`);
                
                // Show error message briefly
                currentVideoTitle.innerText = `⚠️ ${{errorMessage}}`;
                currentVideoChannel.innerText = 'Skipping...';
                
                // Automatically skip to next video after 1 second
                setTimeout(() => {{
                    playNext();
                }}, 1000);
            }}
            
            // Load music based on current mood
            async function loadMoodMusic() {{
                try {{
                    console.log(`Loading music for mood: ${{currentMood}}`);
                    
                    // Show loading state on the selected mood display
                    selectedMoodDisplay.innerText = 'Loading music...';
                    
                    // Request more videos to account for unavailable ones
                    const response = await fetch(`/youtube/search/by-mood/${{currentMood}}?max_results=15`);
                    
                    if (!response.ok) {{
                        const errorData = await response.json();
                        throw new Error(errorData.detail || 'Failed to load music');
                    }}
                    
                    const data = await response.json();
                    console.log('YouTube videos loaded:', data);
                    
                    if (data.videos && data.videos.length > 0) {{
                        videoQueue = data.videos;
                        currentVideoIndex = 0;
                        
                        // Show UI elements
                        currentVideoInfo.style.display = 'flex';
                        youtubeControls.style.display = 'flex';
                        youtubeQueueSection.style.display = 'flex';
                        
                        // Restore mood display
                        const moodInfo = moodButtons[currentMood];
                        selectedMoodDisplay.innerText = `Current: ${{moodInfo.label}} ${{moodInfo.emoji}}`;
                        
                        // Start playing first video
                        playVideo(0);
                        updateQueueDisplay();
                    }} else {{
                        alert('No music found for your mood. Please try again.');
                        const moodInfo = moodButtons[currentMood];
                        selectedMoodDisplay.innerText = `Current: ${{moodInfo.label}} ${{moodInfo.emoji}}`;
                    }}
                    
                }} catch (error) {{
                    console.error('Error loading mood music:', error);
                    alert(`Error loading music: ${{error.message}}`);
                    const moodInfo = moodButtons[currentMood];
                    selectedMoodDisplay.innerText = `Current: ${{moodInfo.label}} ${{moodInfo.emoji}}`;
                }}
            }}
            
            // Play specific video from queue
            function playVideo(index) {{
                if (index < 0 || index >= videoQueue.length) return;
                
                currentVideoIndex = index;
                const video = videoQueue[index];
                
                // Initialize or load video
                if (!player) {{
                    initializeYouTubePlayer(video.video_id);
                }} else {{
                    player.loadVideoById(video.video_id);
                }}
                
                // Update UI
                currentVideoTitle.innerText = video.title;
                currentVideoChannel.innerText = video.channel;
                updateQueueDisplay();
            }}
            
            // Play next video
            function playNext() {{
                if (currentVideoIndex < videoQueue.length - 1) {{
                    playVideo(currentVideoIndex + 1);
                }} else {{
                    console.log('End of queue');
                }}
            }}
            
            // Play previous video
            function playPrevious() {{
                if (currentVideoIndex > 0) {{
                    playVideo(currentVideoIndex - 1);
                }} else {{
                    console.log('Already at first video');
                }}
            }}
            
            // Update queue display
            function updateQueueDisplay() {{
                if (videoQueue.length === 0) {{
                    ytQueueList.innerHTML = 'No videos in queue';
                    return;
                }}
                
                const upcomingVideos = videoQueue.slice(currentVideoIndex + 1, currentVideoIndex + 4);
                ytQueueList.innerHTML = upcomingVideos.map((video, idx) => {{
                    return `<div class="mb-1">${{idx + 1}}. ${{video.title}}</div>`;
                }}).join('') || 'No more videos';
            }}
            
            // Set up event listeners
            if (ytPrevBtn) {{
                ytPrevBtn.addEventListener('click', playPrevious);
            }}
            
            if (ytNextBtn) {{
                ytNextBtn.addEventListener('click', playNext);
            }}
            
            // Initialize with default mood (calm) highlighted
            if (moodCalmBtn) {{
                moodCalmBtn.classList.add('ring-2', 'ring-offset-2', 'ring-purple-500', 'font-bold');
            }}
            
            // Initialize with timer off (default)
            if (timerOffBtn) {{
                timerOffBtn.classList.add('ring-2', 'ring-offset-2', 'ring-blue-500', 'font-bold');
            }}
            
            // Make onYouTubeIframeAPIReady available globally
            window.onYouTubeIframeAPIReady = onYouTubeIframeAPIReady;
            
        }}, 500);
    ''', timeout=5.0)


@ui.page("/users/{username}/journal")
async def user_journal_page(username: str, user_repo: UserRepositoryV2 = Depends(get_user_repository_v2), mood_log_repo: MoodLogRepositoryV2 = Depends(get_mood_log_repository_v2)):
    authenticated_user = await require_auth(username)
    if not authenticated_user:
        return
    
    user = await user_repo.get_by_name(username)
    if not user: 
        ui.label("User not found.")
        return
    
    ui.add_head_html('''
        <style>
            body {
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
            }
            .dashboard-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            }
            .nav-link {
                transition: all 0.3s ease;
                padding: 8px 16px;
                border-radius: 8px;
            }
            .nav-link:hover {
                background: rgba(255, 255, 255, 0.1);
            }
            .dashboard-card {
                transition: all 0.3s ease;
                border-radius: 16px;
                background: white;
            }
            .dashboard-card:hover {
                transform: translateY(-4px);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
            }
        </style>
    ''')
    
    with ui.header().classes('dashboard-header justify-between items-center px-8 py-4'):
        with ui.row().classes('items-center gap-2'):
            ui.label('💭').classes('text-3xl')
            ui.label('Mindfuly').classes('text-2xl font-bold text-white')
        with ui.row().classes("gap-6 items-center"):
            ui.link("Overview", f"/users/{username}/home").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Journal", f"/users/{username}/journal").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Analytics", f"/users/{username}/analytics").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Settings", f"/users/{username}/settings").classes("nav-link text-white text-base font-medium no-underline")
            ui.button('🚪 Logout', on_click=lambda: handle_logout()).classes('bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg font-medium')

    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.notify('Logged out successfully', color='green', icon='check_circle')
        ui.navigate.to('/home')

    with ui.column().classes('w-full items-center mt-10 mb-8 px-4'):
        ui.label(f"{username}'s Journal").classes('text-4xl font-bold text-center mb-1 text-gray-800')

    mood_logs = await mood_log_repo.get_mood_logs(user.id, limit=20)

    with ui.column().classes('w-full max-w-4xl mx-auto px-4'):
        if not mood_logs:
            with ui.card().classes('dashboard-card p-8 text-center'):
                ui.label("No journal entries found. Start logging your mood today!").classes("text-gray-600 italic text-lg")
        else:
            for log in mood_logs:
                with ui.card().classes("dashboard-card p-6 mb-4"):
                    with ui.row().classes("justify-between items-center mb-2"):
                        ui.label(f"Mood: {log.mood_value}").classes("font-semibold text-lg text-purple-600")
                        ui.label(f"Energy: {log.energy_level}").classes("font-semibold text-lg text-blue-600")
                        ui.label(f"Created on: {log.created_at.date()}").classes("text-gray-500 text-sm")
                    if log.notes:
                        ui.label(log.notes).classes("mt-2 text-gray-700")


@ui.page("/users/{username}/analytics")
async def user_analytics_page(username: str, user_repo: UserRepositoryV2 = Depends(get_user_repository_v2), mood_log_repo: MoodLogRepositoryV2 = Depends(get_mood_log_repository_v2)):
    authenticated_user = await require_auth(username)
    if not authenticated_user:
        return
    
    user = await user_repo.get_by_name(username)
    if not user: 
        ui.label("User not found.")
        return
    
    ui.add_head_html('''
        <style>
            body {
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
            }
            .dashboard-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            }
            .nav-link {
                transition: all 0.3s ease;
                padding: 8px 16px;
                border-radius: 8px;
            }
            .nav-link:hover {
                background: rgba(255, 255, 255, 0.1);
            }
            .dashboard-card {
                transition: all 0.3s ease;
                border-radius: 16px;
                background: white;
            }
            .dashboard-card:hover {
                transform: translateY(-4px);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
            }
        </style>
    ''')
    
    with ui.header().classes('dashboard-header justify-between items-center px-8 py-4'):
        with ui.row().classes('items-center gap-2'):
            ui.label('💭').classes('text-3xl')
            ui.label('Mindfuly').classes('text-2xl font-bold text-white')
        with ui.row().classes("gap-6 items-center"):
            ui.link("Overview", f"/users/{username}/home").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Journal", f"/users/{username}/journal").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Analytics", f"/users/{username}/analytics").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Settings", f"/users/{username}/settings").classes("nav-link text-white text-base font-medium no-underline")
            ui.button('🚪 Logout', on_click=lambda: handle_logout()).classes('bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg font-medium')

    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.notify('Logged out successfully', color='green', icon='check_circle')
        ui.navigate.to('/home')

    with ui.column().classes('w-full items-center mt-10 mb-8 px-4'):
        ui.label(f"{username}'s Analytics").classes('text-4xl font-bold text-center mb-1 text-gray-800')

    running_means = await mood_log_repo.get_running_means(user.id, limit=20)
    mood_logs = await mood_log_repo.get_mood_logs(user.id, limit=20)

    if not mood_logs:
        with ui.card().classes('dashboard-card p-8 text-center max-w-4xl mx-auto mt-6'):
            ui.label("Not enough data to display analytics. Start logging your mood today!").classes("text-gray-600 italic text-lg")
    else:
        dates = [entry["date"] for entry in running_means][::-1]
        mood_values = [entry["avg_mood"] for entry in running_means][::-1]
        energy_values = [entry["avg_energy"] for entry in running_means][::-1]

        with ui.card().classes("dashboard-card p-6 max-w-4xl mx-auto mt-6"):
            with ui.row().classes("justify-center w-full mb-4"):
                ui.label("Your Mood and Energy").classes("text-xl font-bold text-center text-gray-800")
            
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

        with ui.card().classes("dashboard-card p-6 max-w-4xl mx-auto mt-6"):
            with ui.row().classes("justify-center w-full mb-4"):
                ui.label("Average Mood and Energy Levels Over Time").classes("text-xl font-bold text-center text-gray-800")

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
    authenticated_user = await require_auth(username)
    if not authenticated_user:
        return
    
    user = await user_repo.get_by_name(username)
    
    ui.add_head_html('''
        <style>
            body {
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
            }
            .dashboard-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            }
            .nav-link {
                transition: all 0.3s ease;
                padding: 8px 16px;
                border-radius: 8px;
            }
            .nav-link:hover {
                background: rgba(255, 255, 255, 0.1);
            }
            .dashboard-card {
                transition: all 0.3s ease;
                border-radius: 16px;
                background: white;
            }
            .dashboard-card:hover {
                transform: translateY(-4px);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
            }
            .input-field {
                border-radius: 12px;
                border: 2px solid #e5e7eb;
                transition: all 0.3s ease;
            }
            .input-field:focus {
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
        </style>
    ''')
    
    async def handle_save():
        current_user = await user_repo.get_by_name(username)
        if not current_user:
            ui.notify("User not found", color="red")
            return

        new_name = name_input.value.strip()
        new_email = email_input.value.strip()

        updated_user = await user_repo.update_user(
            current_user,
            new_name or None,
            new_email or None,
        )

        ui.notify("User Information Updated!", color="green", icon='check_circle')
        await asyncio.sleep(0.7)

        if updated_user.name != username:
            ui.navigate.to(f"/users/{updated_user.name}/settings")
        else:
            ui.navigate.reload()

    async def handle_delete():
        current_user = await user_repo.get_by_name(username)
        if not current_user:
            ui.notify("User not found", color="red")
            return
    
        await user_repo.delete(current_user.id)
        ui.notify("User Deleted Successfully!", color="green", icon='check_circle')
        await asyncio.sleep(0.7)
        await ui.run_javascript("localStorage.clear()")
        ui.navigate.to("/home")

    with ui.header().classes('dashboard-header justify-between items-center px-8 py-4'):
        with ui.row().classes('items-center gap-2'):
            ui.label('💭').classes('text-3xl')
            ui.label('Mindfuly').classes('text-2xl font-bold text-white')
        with ui.row().classes("gap-6 items-center"):
            ui.link("Overview", f"/users/{username}/home").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Journal", f"/users/{username}/journal").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Analytics", f"/users/{username}/analytics").classes("nav-link text-white text-base font-medium no-underline")
            ui.link("Settings", f"/users/{username}/settings").classes("nav-link text-white text-base font-medium no-underline")
            ui.button('🚪 Logout', on_click=lambda: handle_logout()).classes('bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg font-medium')

    async def handle_logout():
        await ui.run_javascript('localStorage.clear()')
        ui.notify('Logged out successfully', color='green', icon='check_circle')
        ui.navigate.to('/home')

    with ui.column().classes("w-full items-center mt-10 px-4"):
        ui.label("User Settings").classes("text-3xl font-bold mb-6 text-gray-800")

        with ui.row().classes("w-full justify-center gap-10 max-w-6xl"):
            with ui.card().classes("dashboard-card p-8 flex-1"):
                ui.label("Account Information").classes("text-xl font-bold mb-4 text-gray-800")
                
                with ui.column().classes("w-full p-4 mb-6 border border-gray-300/40 rounded-xl bg-gray-50/30"):
                    ui.label(f"Username: {user.name}").classes("mb-2 text-gray-700")
                    ui.label(f"Email: {user.email}").classes("mb-4 text-gray-700")

                ui.label("Update Information").classes("text-xl font-bold mb-4 text-gray-800")
                name_input = ui.input("Display name", value=user.name).classes("input-field mb-3 w-full")
                email_input = ui.input("Email", value=user.email).classes("input-field mb-3 w-full")
                ui.button("💾 Save changes", on_click=handle_save).classes('btn-primary text-white px-6 py-3 rounded-lg mt-4')
        
            with ui.card().classes("dashboard-card p-8 flex-1"):
                ui.label("Danger Zone").classes("text-xl font-bold mb-4 text-red-500")

                def show_delete_confirmation():
                    with ui.dialog() as dialog:
                        with ui.card().classes("p-6 rounded-xl shadow-lg w-[450px]"):
                            ui.label("Are you sure you want to delete your account?").classes("text-lg font-medium mb-6 text-center text-gray-800")
                            ui.label("This action cannot be undone.").classes("text-sm text-gray-600 mb-6 text-center")
                            with ui.row().classes("w-full justify-center gap-4"):
                                ui.button("Cancel", on_click=dialog.close).classes("bg-gray-300 hover:bg-gray-400 text-white px-6 py-2 rounded-lg")
                                ui.button("Delete", on_click=lambda: (handle_delete(), dialog.close())).classes("bg-red-500 hover:bg-red-600 text-white px-6 py-2 rounded-lg")
                        dialog.open()
                
                ui.button("🗑️ Delete Account", on_click=show_delete_confirmation).classes('bg-red-500 hover:bg-red-600 text-white px-6 py-3 rounded-lg')




