import pandas as pd
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = "Import users from an Excel file"

    def add_arguments(self, parser):
        parser.add_argument('file_path', type=str, help="Path to the Excel file")

    def handle(self, *args, **kwargs):
        file_path = kwargs['file_path']
        df = pd.read_excel(file_path)

        users = []
        for _, row in df.iterrows():
            if not User.objects.filter(username=row['username']).exists():
                user = User(
                    username=row['username'],
                    email=row['email']
                )
                user.set_password(row['password'])  # Hash the password
                users.append(user)

        User.objects.bulk_create(users)
        self.stdout.write(self.style.SUCCESS(f'Successfully imported {len(users)} users!'))
