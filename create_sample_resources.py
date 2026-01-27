# create_sample_resources.py
from app import create_app
from app.api_models import db
from app.models.user import GovernmentDocument, User
from datetime import datetime

app = create_app()

with app.app_context():
    # Find an admin user to own the resources
    admin = User.query.filter_by(user_class='admin').first()
    if not admin:
        print("No admin user found. Please create an admin user first.")
        exit(1)
    
    sample_resources = [
        # ... (same sample resources as above)
    ]
    
    for resource_data in sample_resources:
        existing = GovernmentDocument.query.filter_by(
            document_id=resource_data['document_id']
        ).first()
        
        if not existing:
            doc = GovernmentDocument(**resource_data)
            db.session.add(doc)
            print(f"Created: {resource_data['document_id']} - {resource_data['title']}")
    
    db.session.commit()
    print(f"\nCreated {len(sample_resources)} sample resources.")