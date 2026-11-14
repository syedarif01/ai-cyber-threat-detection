import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker


# Load environment variables from the project root .env file
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


# Create PostgreSQL database connection URL
database_url = URL.create(
     drivername="postgresql+pg8000",
    username=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "5432")),
    database=os.getenv("DB_NAME"),
)


# Create SQLAlchemy Base
Base = declarative_base()


# Create database engine
engine = create_engine(database_url)


# Create database session
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# Test PostgreSQL database connection
if __name__ == "__main__":
    try:
        with engine.connect() as connection:
            result = connection.execute(
                text("SELECT current_database()")
            )

            print(
                "Connected to database:",
                result.scalar()
            )

    except Exception as error:
        print("Database connection failed:", error)

    finally:
        engine.dispose()