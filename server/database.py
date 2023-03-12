import motor.motor_asyncio

from decouple import config

atlas_config = config('MONGODB_URL')
database=config('MONGODB_DATABASE')
client = motor.motor_asyncio.AsyncIOMotorClient(atlas_config)
db = client[database]
users_collection = db['users']
messages_collection = db['messages']