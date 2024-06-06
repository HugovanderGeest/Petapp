import csv

@app.route('/import_users')
def import_users():
    with open('users.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            user = User(
                username=row['username'],
                password=row['password'],  # Assuming passwords are already hashed
                email=row['email'],
                phone_number=row['phone_number'],
                location_id=row['location_id'] if row['location_id'] else None,
                is_admin=row['is_admin'] == 'True'
            )
            db.session.add(user)
        db.session.commit()
    return "Users imported successfully."
