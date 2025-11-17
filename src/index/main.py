from fastapi import Depends, HTTPException, Request, Response, Cookie
from fastapi.responses import RedirectResponse
from nicegui import ui, app
from pydantic import parse_obj_as
from contextlib import contextmanager
import logging
import copy
from datetime import timedelta
from typing import Optional

from src.mindfuly.routes.users import create_user
from user_service_v2.models.user import UserSchema, get_user_repository_v2, UserRepositoryV2
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
async def user_home_screen(username: str, user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)):
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
            ui.link("My Analytics", "#").classes("text-white text-lg no-underline")
            ui.link("Settings", "#").classes("text-white text-lg no-underline")
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
            ui.label("Adjust the slider based on your mood!").classes("text-lg text-gray-600 font-semibold mb-6 text-center")
            
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

        # Music
        with ui.card().classes("basis-1/4 p-6 shadow rounded-2xl h-full border items-center"):
            ui.label("Music Sessions").classes("text-xl font-bold mb-4 text-center")
            ui.label("Focus Music").classes("text-lg mb-4")
            ui.icon("play_circle").classes("text-5xl text-blue-500 mb-3")
            ui.button("1-Min Refresher").classes("w-full mb-2 bg-blue-500 text-white")
            ui.button("3-Min Calm Down").classes("w-full bg-blue-500 text-white")

        # Daily Overview + Weather
        with ui.card().classes("flex-1 p-6 shadow rounded-2xl h-full border items-center"):
            ui.label("Daily Summary").classes("text-xl font-bold mb-4 text-center")

            with ui.column().classes("items-center mb-4"):
                ui.label("😊").classes("text-6xl mb-2")
                ui.label("Weather for the day.").classes("text-gray-600")

            with ui.column().classes("bg-yellow-50 rounded-xl border p-4"):
                ui.label("Daily Tip").classes("font-semibold mb-1")
                ui.label("You feel happy on a certain day... (example)").classes("text-gray-700")

    # Notes
    with ui.card().classes("w-full max-w-7xl mx-auto mt-10 p-6 shadow rounded-2xl items-center border"):
        ui.label("What's on your mind today?").classes("text-xl font-bold mb-4")
        textarea = ui.textarea(placeholder="Write your notes here...").classes("w-full mb-4").props("outlined autogrow rows=4")
        ui.button("SAVE NOTES", on_click=lambda: ui.notify("Note Submitted!")).classes("bg-blue-500 text-white w-full py-2 rounded-lg")