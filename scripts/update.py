from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from models import Address, Base
from datetime import datetime, timezone

DATABASE_URL = "postgresql://user:password@localhost/scamexplorer"
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Load all addresses
addresses = session.query(Address).all()

for address in addresses:
    if address.blacklist_category is None:
        address.blacklist_category = 'N/A'
    if address.blacklist_search_result is None:
        address.blacklist_search_result = 'Not found in blacklist'
    if address.phishing_dataset_check is None:
        address.phishing_dataset_check = 'Not found in phishing dataset'
    if address.transaction_tracing_result is None:
        address.transaction_tracing_result = 'No evidence of links to known blacklisted wallets'
    if address.whitelist_search_result is None:
        address.whitelist_search_result = 'Not found in our whitelist of known entities'

session.commit()
session.close()
print("Database updated successfully")
