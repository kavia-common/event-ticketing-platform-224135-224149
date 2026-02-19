from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.api.core.settings import get_settings

engine = create_async_engine(
    get_settings().postgres_url,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# PUBLIC_INTERFACE
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an Async SQLAlchemy session."""
    async with AsyncSessionLocal() as session:
        yield session
