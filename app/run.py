from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    db.create_all()

    if User.query.count() == 0:
        # Default users
        admin = User(username='admin')
        user1 = User(username='user1')
        user2 = User(username='user2')

        # Use the set_password method to hash the passwords
        admin.set_password('admin123')
        user1.set_password('letmein')
        user2.set_password('welcome123')

        db.session.add_all([admin, user1, user2])
        db.session.commit()
        print("Seeded default users: admin, user1, user2 with hashed passwords")

if __name__ == '__main__':
    app.run(debug=True)