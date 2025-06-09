from django.conf import settings
import redis

redis_client = redis.StrictRedis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    username=settings.REDIS_USER,
    password=settings.REDIS_PASSWORD,
    decode_responses=True,
)
