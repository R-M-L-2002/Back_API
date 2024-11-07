from repositories.user_repository import UserRepository
from werkzeug.security import generate_password_hash


class UserService:
    def __init__(self):
        self.user_repository = UserRepository()

    def fetch_users(self):
        return self.user_repository.get_all_users()

    def add_user(self, username, password):
        hashed_password = generate_password_hash(password, method="sha256")
        return self.user_repository.create_user(username, hashed_password)

    def modify_user(self, user_id, username, password):
        hashed_password = generate_password_hash(password, method="sha256")
        return self.user_repository.update_user(user_id, username, hashed_password)

    def remove_user(self, user_id):
        return self.user_repository.delete_user(user_id)
