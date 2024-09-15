import redis.asyncio as redis

redis_client = redis.from_url("redis://localhost", decode_responses=True)
