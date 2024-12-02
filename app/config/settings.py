import os
from typing import Optional

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Load environment variables from .env file
load_dotenv(dotenv_path="env/.env")


class Settings(BaseSettings):
    """
    Settings class to manage configuration variables.
    """

    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL")
    DATABASE_NAME: Optional[str] = os.getenv("DATABASE_NAME")
    SECRET_KEY: Optional[str] = os.getenv("SECRET_KEY")
    ALGORITHM: Optional[str] = os.getenv("ALGORITHM")
    MAIL_USERNAME: Optional[str] = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD: Optional[str] = os.getenv("MAIL_PASSWORD")
    MAIL_FROM: Optional[str] = os.getenv("MAIL_FROM")
    MAIL_PORT: Optional[int] = int(os.getenv("MAIL_PORT", 587))
    MAIL_SERVER: Optional[str] = os.getenv("MAIL_SERVER")
    MAIL_STARTTLS: Optional[bool] = os.getenv("MAIL_STARTTLS", "False") == "True"
    MAIL_SSL_TLS: Optional[bool] = os.getenv("MAIL_SSL_TLS", "False") == "True"
    USE_CREDENTIALS: Optional[bool] = os.getenv("USE_CREDENTIALS", "True") == "True"
    VALIDATE_CERTS: Optional[bool] = os.getenv("VALIDATE_CERTS", "True") == "True"
    NEO4J_URI: Optional[str] = os.getenv("URI")
    NEO4J_USERNAME: Optional[str] = os.getenv("USERNAME")
    NEO4J_PASSWORD: Optional[str] = os.getenv("PASSWORD")


settings = Settings()
