from mongoengine import Document, fields, ReferenceField
from .models import User
class Message(Document):
    sender = ReferenceField(User)
    recipient = ReferenceField(User)
    text = fields.StringField()
    file = fields.StringField()
    created_at = fields.DateTimeField(default=datetime.utcnow)