def create_admin_user(username, password):
    admin = User(username=username, password=password, is_admin=True)
    db.session.add(admin)
    db.session.commit()
    print(f'Admin user {username} created successfully.')
