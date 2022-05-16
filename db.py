from enum import Enum

from tortoise import Model, fields, Tortoise

from config import DB_URL


class User(Model):
    id = fields.IntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    name = fields.CharField(max_length=255)
    password = fields.CharField(max_length=255)

    def __str__(self):
        return self.name


class Post(Model):
    id = fields.CharField(128, pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    body = fields.JSONField()

    def __str__(self):
        return self.id


async def init():
    await Tortoise.init(
        db_url=DB_URL,
        modules={'models': ['db']}
    )
    await Tortoise.generate_schemas()
