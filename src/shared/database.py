from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

import os
from dotenv import load_dotenv

engine = None
def get_db():
    global engine
    if not engine:
        host = os.environ['DATABASE_HOST']
        username = os.environ['DATABASE_USER']
        password = os.environ['DATABASE_PASSWORD']
        dbname = os.environ['DATABASE_NAME']

        DATABASE_URL = f"postgresql+psycopg2://{username}:{password}@{host}:5432/{dbname}"

        engine = create_engine(DATABASE_URL)

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()