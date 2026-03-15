@echo off
:: Start Django backend
start cmd /k ".\venv\Scripts\activate && cd api && python.exe .\manage.py runserver"

:: Delay to ensure backend starts first
timeout /t 5 /nobreak >nul

:: Open default browser with the specified links
start "" "http://127.0.0.1:8000/admin/"
