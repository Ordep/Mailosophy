#!/usr/bin/env python
"""
Mailosophy - Email Organization Web Application
Main entry point for the Flask application
"""
import os
from app import create_app

if __name__ == '__main__':
    app = create_app()
    
    # Create database tables
    with app.app_context():
        from app import db
        # Create tables if they don't exist (without dropping existing data)
        db.create_all()
    
    # Run development server
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug, host='0.0.0.0', port=5000)
