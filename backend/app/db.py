from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


config = settings()
engine = create_engine(config.database_url, pool_pre_ping=True, pool_size=config.db_pool_size,
                       max_overflow=config.db_max_overflow, connect_args={'connect_timeout': 5})
Session = sessionmaker(engine, expire_on_commit=False)


def get_db():
    with Session() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
