from fastapi import FastAPI
from sqlalchemy import create_engine, Column, String, Integer, func
from sqlalchemy.orm import sessionmaker, declarative_base
from typing import List, Dict

# Database connection parameters
print('Please enter the database parameters')
DATABASE_URI = (f'postgresql://{input('Username:')}:{input('Password:')}'
                f'@localhost:{input('Port:')}/{input('Database name:')}')

# SQLAlchemy setup
Base = declarative_base()


# Define the Vuln table as a SQLAlchemy model
class Vuln(Base):
    __tablename__ = 'vuln'
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String)
    endpoint = Column(String)
    severity = Column(String)
    cve = Column(String)
    description = Column(String)
    sensor = Column(String)


# Create an engine and session
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

# Initialize FastAPI app
app = FastAPI()


@app.get("/vulnerabilities", response_model=List[Dict])
def get_vulnerabilities():
    session = Session()
    try:
        # Query to find records with the same endpoint and cve
        subquery = session.query(
            Vuln.endpoint,
            Vuln.cve,
            func.count('*').label('count')
        ).group_by(
            Vuln.endpoint,
            Vuln.cve
        ).having(func.count('*') > 1).subquery()

        # Fetching all records that match the duplicate criteria
        results = session.query(
            Vuln.title,
            Vuln.endpoint,
            Vuln.severity,
            Vuln.cve,
            Vuln.description,
            Vuln.sensor
        ).join(subquery, (Vuln.endpoint == subquery.c.endpoint) & (Vuln.cve == subquery.c.cve)).all()

        # Group records by (endpoint, cve)
        grouped_data = {}
        for record in results:
            endpoint, cve = record.endpoint, record.cve
            key = (endpoint, cve)
            if key not in grouped_data:
                grouped_data[key] = []
            grouped_data[key].append({
                "title": record.title,
                "endpoint": endpoint,
                "severity": record.severity,
                "cve": cve,
                "description": record.description,
                "sensor": record.sensor
            })

        # Format output with unique tags
        output = []
        for idx, ((endpoint, cve), group) in enumerate(grouped_data.items(), start=1):
            tag = f"group_{idx}"
            for item in group:
                item["tag"] = tag
                output.append(item)

        return output

    except Exception as e:
        print(f"Error: {e}")
        return []

    finally:
        session.close()
