import sys
import os

# Point to your application directory
# Change this path if your application is located elsewhere
project_home = '/var/www/html/cryptopix-bridge'

if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set up logging to stderr (Apache error log)
import logging
logging.basicConfig(stream=sys.stderr)

# Activate the virtual environment
# This assumes your venv is located at /var/www/html/cryptopix-bridge/venv
activate_this = os.path.join(project_home, 'venv/bin/activate_this.py')
if os.path.exists(activate_this):
    with open(activate_this) as file_:
        exec(file_.read(), dict(__file__=activate_this))

# Import the Flask application
# 'app.main' matches your directory structure (app/main.py)
from app.main import app as application
