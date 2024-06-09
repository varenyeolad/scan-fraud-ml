import pytest
from datetime import datetime, timezone
from app import app, update_addresses
from models import Address, engine, Session

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            # Setup database connection
            yield client

def test_trigger_update(client):
    session = Session()
    
    # Clean up the existing address if it exists
    session.query(Address).filter(Address.address == "0x0178499f84c76c9b863318703092080f31dfa1ae").delete()
    session.commit()

    # Add a test address to the database
    test_address = Address(
        address="0x0178499f84c76c9b863318703092080f31dfa1ae",
        risk_score=0.5,
        risk_reason="Initial test reason",
        overall_assessment="Medium Risk",
        total_transactions=5,
        total_received=1.0,
        total_sent=0.5,
        current_balance=0.5,
        last_scanned=datetime.now(timezone.utc)
    )
    session.add(test_address)
    session.commit()

    # Trigger the update
    response = client.post('/trigger-update')
    assert response.status_code == 200
    assert response.json == {"message": "Update triggered successfully"}

    # Verify the updated data
    updated_address = session.query(Address).filter(Address.address == "0x0178499f84c76c9b863318703092080f31dfa1ae").first()
    assert updated_address.risk_score != 0.5  # Ensure the risk score has been updated
    assert updated_address.last_scanned > test_address.last_scanned  # Ensure the last_scanned field is updated

    session.close()
