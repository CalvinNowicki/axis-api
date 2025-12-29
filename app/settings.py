from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "AXIS API"
    aws_region: str = "us-west-2"

    # Dynamo tables (V1: 3-table model, easy + clear)
    table_rings: str = "axis_rings"
    table_trackers: str = "axis_trackers"
    table_bricks: str = "axis_bricks"

settings = Settings()
