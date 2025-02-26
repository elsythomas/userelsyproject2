# Generated by Django 5.1.6 on 2025-02-26 06:40

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0012_user_role_alter_role_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='role',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='myapp.role'),
        ),
        migrations.AlterField(
            model_name='role',
            name='id',
            field=models.IntegerField(choices=[(1, 'Admin'), (2, 'Teacher'), (3, 'Student')], primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='role',
            name='name',
            field=models.CharField(max_length=50, unique=True),
        ),
    ]
