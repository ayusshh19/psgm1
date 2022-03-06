from calendar import c
from msilib.schema import Class
from django.db import models

# Create your models here.
class reg(models.Model):
    Fname=models.CharField(max_length=100, blank=False, null=False)
    Mname=models.CharField(max_length=100, blank=False, null=False)
    Lname=models.CharField(max_length=100, blank=False, null=False)
    Username=models.CharField(max_length=100, blank=False, null=False)
    Email=models.EmailField(max_length=100, blank=False, null=False)
    Address=models.CharField(max_length=300, blank=False, null=False)
    phone_number=models.CharField(max_length=100, blank=False, null=False)
    pan_no=models.CharField(max_length=100, blank=False, null=False)
    pass1=models.CharField(max_length=100, blank=False, null=False)
    user_type=models.CharField(max_length=100, blank=False, null=False)
    class Meta:
        db_table = 'signup'
class Passwords(models.Model):

    id = models.AutoField(primary_key=True)
    failed_attempts = models.IntegerField(default=0)
    failed_attempt_time = models.DateTimeField(auto_now=True,blank=True, null=True)
    last_login_on = models.DateTimeField(auto_now=True,blank=True,null=True)
    last_reset_on = models.DateTimeField(auto_now=True,blank=True, null=True)
    last_reset_date = models.DateField(auto_now=True,blank=True, null=True)
    last_reset_time = models.TimeField(auto_now=True,blank=True, null=True)
    unlocks_on = models.DateTimeField(auto_now=True,blank=True,null=True)
    value = models.CharField(max_length=255, blank=True, null=True)
    passwords_changed = models.IntegerField(default=0)
    user = models.ForeignKey(reg,related_name='PASSWORD',on_delete=models.CASCADE)
    isdefault = models.BooleanField(default=True)
    class Meta:
        db_table = 'passwords'

class PasswordHistory(models.Model):

    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(reg,on_delete=models.DO_NOTHING,blank=True,null=True)
    changed_on = models.DateTimeField(auto_now_add=True)
    new_password = models.CharField(max_length=255,blank=True, null=True)
    old_password = models.CharField(max_length=255,blank=True, null=True)

    class Meta:
        db_table = 'passwords_history'


class LoginLogs(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(reg, related_name='ATTEMPTS', blank=True, null=True, on_delete=models.CASCADE)
    login_status = models.BooleanField(blank=True, null=True)
    cause = models.CharField(max_length=255, blank=True, null=True)
    log_date = models.DateTimeField(blank=True, null=True)
    request_page = models.CharField(max_length=255, blank=True, null=True)
    time_zone = models.CharField(max_length=255, blank=True, null=True)
    isactive = models.IntegerField(default=1)

    class Meta:
        db_table = 'login_logs'


class PasswordResetLogs(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(reg, related_name='RESETS', blank=True, null=True, on_delete=models.CASCADE)
    forgot_token = models.CharField(max_length=255, blank=True, null=True)
    attempts = models.IntegerField(default=0)
    request_date = models.DateField(auto_now=True,blank=True, null=True)
    expires_on = models.DateTimeField(auto_now=True,blank=True, null=True)
    isactive = models.IntegerField(default=0)

    class Meta:
        db_table = 'password_reset_logs'

class Tokens(models.Model):
    id = models.AutoField(primary_key=True)
    value = models.CharField(max_length=255)
    valid_upto = models.DateTimeField(auto_now=True,blank=True, null=True)
    user = models.ForeignKey(reg, related_name='TOKEN', on_delete=models.CASCADE)

    class Meta:
        db_table = 'tokens'
        
class home(models.Model):       
    owner_id= models.ForeignKey(reg,default=1, on_delete=models.CASCADE)
    rent=models.CharField(max_length=200,blank=True, null=True)
    about_room=models.CharField(max_length=300,blank=True, null=True)
    room_img=models.URLField()

    
    class Meta:
        db_table = 'home'

class delete_account(models.Model):
    Username=models.CharField(max_length=100, blank=False, null=False)
    Email=models.EmailField(max_length=100, blank=False, null=False)       
    pass1=models.CharField(max_length=100, blank=False, null=False)
    
    class Meta:
        db_table = 'del_acc'