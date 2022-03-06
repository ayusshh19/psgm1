from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = reg
        abstract =True
        fields = '__all__'

class passwordserializer(serializers.ModelSerializer):
    class Meta:
        model = Passwords
        abstract =True
        fields = '__all__'
        
class homeserializer(serializers.ModelSerializer):
    class Meta:
        model = home
        abstract =True
        fields = '__all__'
        
class delserializer(serializers.ModelSerializer):
    class Meta:
        model = delete_account
        abstract =True
        fields = '__all__'