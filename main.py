import os
from dotenv import load_dotenv

# Load .env from server directory if it exists (for local testing)
dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server', '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

# Import the FastAPI app from the server/main.py
from server.main import app
