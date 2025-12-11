# init_indexes.py
import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MASTER_DB = os.getenv("MASTER_DB", "master_db")

async def create_indexes():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[MASTER_DB]
    col = db["organizations"]
    await col.create_index("organization_name", unique=True)
    await col.create_index("admin.email", unique=True)
    print("Indexes created")

if __name__ == "__main__":
    asyncio.run(create_indexes())
