import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Gunicorn configuration variables
bind = "127.0.0.1:8000"
workers = 4
