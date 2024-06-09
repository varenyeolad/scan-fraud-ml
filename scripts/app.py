from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint
import logging
from apscheduler.schedulers.background import BackgroundScheduler

from config import redis_client, limiter, SWAGGER_URL, API_URL
from models import engine
from routes import blueprint as routes_blueprint
from services import update_addresses

app = Flask(__name__)

# Configure Limiter
limiter.init_app(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Swagger UI configuration
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Scam Explorer API",
        'validatorUrl': None,  # Disable the online validator, optional
        'apikey': True  # Show the API key input field
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Register routes
app.register_blueprint(routes_blueprint)

# Periodic update of addresses
scheduler = BackgroundScheduler()
scheduler.add_job(update_addresses, 'interval', hours=24)  # Update every 24 hours
scheduler.start()

if __name__ == '__main__':
    app.run(debug=True)
