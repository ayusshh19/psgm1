# Generated by Django 4.0.2 on 2022-03-04 16:01

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0004_alter_owner_reg_phone_number'),
    ]

    operations = [
        migrations.CreateModel(
            name='home',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rent', models.CharField(blank=True, max_length=200, null=True)),
                ('about_room', models.CharField(blank=True, max_length=300, null=True)),
                ('room_img', models.URLField()),
                ('pass1', models.CharField(max_length=20)),
            ],
            options={
                'db_table': 'home',
            },
        ),
        migrations.CreateModel(
            name='LoginLogs',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('login_status', models.BooleanField(blank=True, null=True)),
                ('cause', models.CharField(blank=True, max_length=255, null=True)),
                ('log_date', models.DateTimeField(blank=True, null=True)),
                ('request_page', models.CharField(blank=True, max_length=255, null=True)),
                ('time_zone', models.CharField(blank=True, max_length=255, null=True)),
                ('isactive', models.IntegerField(default=1)),
            ],
            options={
                'db_table': 'login_logs',
            },
        ),
        migrations.CreateModel(
            name='PasswordHistory',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('changed_on', models.DateTimeField(auto_now_add=True)),
                ('new_password', models.CharField(blank=True, max_length=255, null=True)),
                ('old_password', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'db_table': 'passwords_history',
            },
        ),
        migrations.CreateModel(
            name='PasswordResetLogs',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('forgot_token', models.CharField(blank=True, max_length=255, null=True)),
                ('attempts', models.IntegerField(default=0)),
                ('request_date', models.DateField(auto_now=True, null=True)),
                ('expires_on', models.DateTimeField(auto_now=True, null=True)),
                ('isactive', models.IntegerField(default=0)),
            ],
            options={
                'db_table': 'password_reset_logs',
            },
        ),
        migrations.CreateModel(
            name='Passwords',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('failed_attempts', models.IntegerField(default=0)),
                ('failed_attempt_time', models.DateTimeField(auto_now=True, null=True)),
                ('last_login_on', models.DateTimeField(auto_now=True, null=True)),
                ('last_reset_on', models.DateTimeField(auto_now=True, null=True)),
                ('last_reset_date', models.DateField(auto_now=True, null=True)),
                ('last_reset_time', models.TimeField(auto_now=True, null=True)),
                ('unlocks_on', models.DateTimeField(auto_now=True, null=True)),
                ('value', models.CharField(blank=True, max_length=255, null=True)),
                ('passwords_changed', models.IntegerField(default=0)),
                ('isdefault', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'passwords',
            },
        ),
        migrations.CreateModel(
            name='reg',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Fname', models.CharField(max_length=100)),
                ('Mname', models.CharField(max_length=100)),
                ('Lname', models.CharField(max_length=100)),
                ('Username', models.CharField(max_length=100)),
                ('Email', models.EmailField(max_length=100)),
                ('Address', models.CharField(max_length=300)),
                ('phone_number', models.CharField(max_length=100)),
                ('pan_no', models.CharField(max_length=100)),
                ('pass1', models.CharField(max_length=100)),
                ('user_type', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'signup',
            },
        ),
        migrations.CreateModel(
            name='Tokens',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('value', models.CharField(max_length=255)),
                ('valid_upto', models.DateTimeField(auto_now=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='TOKEN', to='home.reg')),
            ],
            options={
                'db_table': 'tokens',
            },
        ),
        migrations.DeleteModel(
            name='applied',
        ),
        migrations.DeleteModel(
            name='approved',
        ),
        migrations.DeleteModel(
            name='Fav_cart',
        ),
        migrations.DeleteModel(
            name='Owner_reg',
        ),
        migrations.DeleteModel(
            name='User_reg',
        ),
        migrations.AddField(
            model_name='passwords',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='PASSWORD', to='home.reg'),
        ),
        migrations.AddField(
            model_name='passwordresetlogs',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='RESETS', to='home.reg'),
        ),
        migrations.AddField(
            model_name='passwordhistory',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='home.reg'),
        ),
        migrations.AddField(
            model_name='loginlogs',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='ATTEMPTS', to='home.reg'),
        ),
    ]
