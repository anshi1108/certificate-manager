# Generated by Django 5.1.4 on 2024-12-26 05:52

import certs.models
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("certs", "0003_certificate_notes_alter_certificate_certificate"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="archived",
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name="certificate",
            name="private_key",
            field=models.FileField(upload_to=certs.models.custom_key_name),
        ),
    ]
