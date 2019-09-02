from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


User1 = User(name="Paul Bunyan", email="paul@ocanada.com")
session.add(User1)
session.commit()

category1 = Category(name="Dogs")

session.add(category1)
session.commit()


item1 = Item(user_id=1, name="Labrador",
             description="Loyal",
             category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Wolf",
             description="Best",
             category=category1)

session.add(item2)
session.commit()


category2 = Category(name="Cats")

session.add(category2)
session.commit()


item1 = Item(user_id=1, name="Persian",
             description="Fluffy",
             category=category2)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Tiger",
             description="Best",
             category=category2)

session.add(item2)
session.commit()


category1 = Category(name="Rodents")

session.add(category1)
session.commit()


item1 = Item(user_id=1, name="Guinea Pig",
             description="Curious.",
             category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Hamster",
             description="Fat",
             category=category1)

session.add(item2)
session.commit()


print("added items!")
