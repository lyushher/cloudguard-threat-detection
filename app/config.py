import os
from dotenv import load_dotenv

load_dotenv()


API_KEY = os.getenv("CLOUDGUARD_API_KEY")

AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")
DYNAMODB_TABLE_NAME = os.getenv(
    "DYNAMODB_TABLE_NAME",
    "CloudGuardIncidents"
)