# Generated by Django 4.0.2 on 2022-03-04 07:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0003_alter_owner_reg_room_img'),
    ]

    operations = [
        migrations.AlterField(
            model_name='owner_reg',
            name='phone_number',
            field=models.CharField(max_length=100),
        ),
    ]