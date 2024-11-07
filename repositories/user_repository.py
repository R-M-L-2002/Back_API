from models import User
from app import db


class UserRepository:
    def __init__(self):
        self.session = db.session

    def get_all_users(self):
        return self.session.query(User).all()

    def get_user_by_id(self, user_id):
        return self.session.query(User).get(user_id)

    def create_user(self, username, password):
        new_user = User(username=username, password=password)
        self.session.add(new_user)
        self.session.commit()
        return new_user

    def delete_user(self, user_id):
        user = self.get_user_by_id(user_id)
        if user:
            self.session.delete(user)
            self.session.commit()
            return True
        return False

    def update_user(self, user_id, username, password):
        user = self.get_user_by_id(user_id)
        if user:
            user.username = username
            user.password = password
            self.session.commit()
            return user
        return None
