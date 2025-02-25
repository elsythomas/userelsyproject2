from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission

class Command(BaseCommand):
    help = 'Seed roles into the database'

    def handle(self, *args, **kwargs):
        roles = ['Admin', 'Teacher', 'Student']

        for role in roles:
            group, created = Group.objects.get_or_create(name=role)
            if created:
                self.stdout.write(self.style.SUCCESS(f'Role "{role}" created successfully'))
            else:
                self.stdout.write(self.style.WARNING(f'Role "{role}" already exists'))

        self.stdout.write(self.style.SUCCESS('Roles seeding completed!'))



