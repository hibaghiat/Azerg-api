import datetime
import secrets

import redis

# Connect to Redis
redis_client = redis.Redis(host="redis", port=6379, db=0)


def generate_unique_token() -> str:
    """Generate a unique random token."""
    token = secrets.token_urlsafe(60)
    return token


def store_token_in_redis(token: str, email: str) -> None:
    """Store token in Redis with an expiration time."""
    expiration_time = datetime.timedelta(minutes=10)
    expiration_seconds = int(expiration_time.total_seconds())
    redis_client.setex(token, expiration_seconds, email)


def check_token_and_get_email(token: str) -> str:
    """Check if token exists in Redis, has not expired, retrieve email, and remove from Redis."""
    email = redis_client.get(token)
    if email:
        # Token exists, retrieve the email and remove token from Redis
        email = email.decode("utf-8")
        redis_client.delete(token)
        return email
    else:
        # Token does not exist or has expired
        return None
