from sqlalchemy import Column, Integer, String, Float, ForeignKey, create_engine
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

class ReportedAddress(Base):
    __tablename__ = 'reported_addresses'
    id = Column(Integer, primary_key=True)
    address_id = Column(Integer, ForeignKey('addresses.id'), nullable=False)
    report_reason = Column(String, nullable=False)
    address = relationship("Address")

# PostgreSQL connection string
DATABASE_URL = "postgresql://user:jaypark18@localhost:5432/scamexplorer"

engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()
