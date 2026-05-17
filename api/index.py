import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel serverless handler
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from werkzeug.serving import run_wsgi

def handler(request, response):
    """Vercel serverless handler"""
    from werkzeug.wrappers import Request

    # Convert Vercel request to WSGI environ
    environ = request

    # Run Flask app
    return app(environ, response)

# For local testing
if __name__ == '__main__':
    app.run(debug=True)
