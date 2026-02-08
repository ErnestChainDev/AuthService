import pymysql
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.engine import Engine

pymysql.install_as_MySQLdb()

class Base(DeclarativeBase):
    pass

def build_mysql_url(host: str, port: str, user: str, password: str, db: str) -> str:
    return f"mysql+pymysql://{user}:{password}@{host}:{port}/{db}"

def make_engine(db_url: str) -> Engine:
    return create_engine(
        db_url,
        pool_pre_ping=True,
        pool_recycle=1800,
        echo=False,
        future=True,
    )

def make_session_factory(engine: Engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

def db_dependency(SessionLocal):
    def _get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()
    return _get_db