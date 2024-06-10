from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, create_engine, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()

class Address(Base):
    __tablename__ = 'addresses'
    id = Column(Integer, primary_key=True)
    address = Column(String, unique=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_reason = Column(String, nullable=False)
    overall_assessment = Column(String, nullable=False)
    total_transactions = Column(Integer, nullable=False)
    total_received = Column(Float, nullable=False)
    total_sent = Column(Float, nullable=False)
    current_balance = Column(Float, nullable=False)
    last_scanned = Column(DateTime, nullable=False)
    blacklist_category = Column(String, nullable=True)
    blacklist_search_result = Column(String, nullable=True)
    phishing_dataset_check = Column(String, nullable=True)
    transaction_tracing_result = Column(String, nullable=True)
    whitelist_search_result = Column(String, nullable=True)

class ReportedAddress(Base):
    __tablename__ = 'reported_addresses'
    id = Column(Integer, primary_key=True)
    address_id = Column(Integer, ForeignKey('addresses.id'), nullable=False)
    report_reason = Column(String, nullable=False)
    address = relationship("Address")

# PostgreSQL connection string
DATABASE_URL = "postgresql://user:jaypark1818@localhost:5432/scamexplorer"

engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

