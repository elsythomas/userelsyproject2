



from django.core.management.base import BaseCommand
from myapp.models import Role  # Import your Role model

class Command(BaseCommand):
    help = 'Seed roles into the database'

    def handle(self, *args, **kwargs):
        roles = ['Admin', 'Teacher', 'Student']

        for role_name in roles:
            role, created = Role.objects.get_or_create(name=role_name)
            if created:
                self.stdout.write(self.style.SUCCESS(f'Role "{role_name}" created successfully'))
            else:
                self.stdout.write(self.style.WARNING(f'Role "{role_name}" already exists'))

        self.stdout.write(self.style.SUCCESS('Roles seeding completed!'))
