"""CyberSpy Database Setup — Async SQLite via SQLAlchemy"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from config import settings
from models import Base

# Use aiosqlite for async SQLite (dev); swap to asyncpg for PostgreSQL in prod
engine = create_async_engine(
    settings.DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite://")
    if "sqlite" in settings.DATABASE_URL and "aiosqlite" not in settings.DATABASE_URL
    else settings.DATABASE_URL,
    echo=settings.DEBUG,
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Create all tables on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """Dependency: yields an async DB session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
