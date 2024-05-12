import os
from dotenv import load_dotenv


class Settings:
    """
    Class for loading environment variables from .env file.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Settings, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            load_dotenv()

    @property
    def VT_API_KEY(self):
        return os.getenv("VT_API_KEY")


settings = Settings()
