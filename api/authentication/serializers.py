from rest_framework import serializers
from djoser.serializers import UserCreateSerializer as BaseUserRegistrationSerializer
from .models import UserModel
        
class UserSerializer(BaseUserRegistrationSerializer):
    class Meta:
        model = UserModel
        fields = '__all__'

class GetUserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = UserModel
        fields = ['id','email','username','name','first_name','last_name',
                  'full_name','initial_profile','is_superuser','is_active','date_joined','last_login']
    
    def get_date_joined(self, obj):
        return obj.date_joined.strftime('%d/%m/%Y')
    def get_last_login(self, obj):
        return obj.last_login.strftime('%d/%m/%Y')
    