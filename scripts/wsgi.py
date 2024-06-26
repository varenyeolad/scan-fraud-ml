import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from app import app

if __name__ == "__main__":
    app.run()
