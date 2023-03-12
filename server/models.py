import motor.motor_asyncio
from bson.objectid import ObjectId
from passlib.hash import bcrypt
from datetime import datetime
from .database import db,client,users_collection,messages_collection
from mongoengine import Document, fields, ReferenceField



class User(Document):
    __collection__ = 'users'
    def __init__(self, username: str, password: str, created_at: datetime = None, _id: str = None):
        self.username = username
        self.password_hash = bcrypt.hash(password)
        self.created_at = created_at or datetime.utcnow()
        self._id = _id or str(ObjectId())

    @classmethod
    async def from_dict(cls, user_dict):
        return cls(
            username=user_dict["username"],
            password=user_dict["password"],
            created_at=user_dict.get("created_at"),
            _id=str(user_dict.get("_id", ObjectId())),
        )

    def to_dict(self):
        return {
            "_id": self._id,
            "username": self.username,
            "password_hash": self.password_hash,
            "created_at": self.created_at,
        }

    @classmethod
    async def create(cls, user: dict):
        user_obj = await cls.from_dict(user)
        await users_collection.insert_one(user_obj.to_dict())
        return user_obj

    @classmethod
    async def get_by_username(cls, username: str):
        user_dict = await users_collection.find_one({"username": username})
        if user_dict is None:
            return None
        return await cls.from_dict(user_dict)
    

    @classmethod
    async def find_one(cls, filter):
        return await db[cls.__collection__].find_one(filter)

    def verify_password(self, password: str):
        return bcrypt.verify(password, self.password_hash)
class Message(Document):
    sender = fields.ReferenceField(User)
    recipient = fields.ReferenceField(User)
    text = fields.StringField()
    file = fields.StringField()
    created_at = fields.DateTimeField(default=datetime.utcnow)

    @classmethod
    async def create(cls, message: dict):
        message_obj = cls(
            sender=message["sender"],
            recipient=message["recipient"],
            text=message["text"],
            file=message["file"],
            created_at=message.get("created_at", datetime.utcnow())
        )
        await messages_collection.insert_one(message_obj.to_dict())
        return message_obj

    @classmethod
    async def get_messages(cls, sender_id: str, recipient_id: str):
        messages = []
        async for message_dict in messages_collection.find({
            "sender.$id": ObjectId(sender_id),
            "recipient.$id": ObjectId(recipient_id)
        }).sort("created_at", 1):
            messages.append(cls.from_dict(message_dict))
        return messages

    @classmethod
    async def from_dict(cls, message_dict):
        return cls(
            sender=message_dict["sender"],
            recipient=message_dict["recipient"],
            text=message_dict["text"],
            file=message_dict["file"],
            created_at=message_dict["created_at"]
        )

    def to_dict(self):
        return {
            "_id": str(self._id),
            "sender": self.sender,
            "recipient": self.recipient,
            "text": self.text,
            "file": self.file,
            "created_at": self.created_at,
        }
