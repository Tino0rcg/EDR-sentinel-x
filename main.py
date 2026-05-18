import os
import sys
from dotenv import load_dotenv

# Add the server directory to python path
current_dir = os.path.dirname(os.path.abspath(__file__))
server_dir = os.path.join(current_dir, 'server')
sys.path.insert(0, server_dir)

# Load .env from server directory if it exists (for local testing)
dotenv_path = os.path.join(server_dir, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

# Import the FastAPI app from the server/main.py
from main import app
