from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views import View
from rest_framework import authentication, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView

from .forms import EmailAuthenticationForm, RegistrationForm
from .models import UserModel
from .serializers import GetUserSerializer, UserSerializer


FIELD_NOT_EMPTY = "field should not be empty."
BAD_REQUEST = status.HTTP_400_BAD_REQUEST
CREATE_REQUEST = status.HTTP_201_CREATED
GET_REQUEST = status.HTTP_200_OK
USER_EXIST = "with the given credentials already exist."
USER_NOT_EXIST = "with the given credentials does not exist."
HOURS = ' hours!'


def validate_user_input(request_data):
    required_fields = ['email', 'first_name', 'last_name', 'password']
    for field in required_fields:
        if not request_data.get(field, '').strip():
            return False, f'{field.capitalize()} should not be empty.'
    return True, 'Success'


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def create_profile(request):
    try:
        request_data = request.data
        is_valid, error = validate_user_input(request_data)
        if not is_valid:
            return Response(error, status=status.HTTP_400_BAD_REQUEST)

        email = request_data.get('email', '').strip()
        first_name = request_data.get('first_name', '').strip()
        last_name = request_data.get('last_name', '').strip()
        password = request_data.get('password', '').strip()
        validate_password(password, user=email, password_validators=None)

        user_data = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': password,
        }

        user_serializer = UserSerializer(data=user_data)
        if user_serializer.is_valid():
            user_serializer.save()
            return Response("User Successfully Created!", status=status.HTTP_201_CREATED)
        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response(str(e), status=status.HTTP_400_BAD_REQUEST)


class Me(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            user = UserModel.objects.filter(id=request.auth.user.pk).order_by('id')
            serializer = GetUserSerializer(instance=user, many=True)
            return Response(serializer.data, status=GET_REQUEST)
        except Exception as e:
            return Response(str(e), status=BAD_REQUEST)


class AuthLoginView(LoginView):
    template_name = 'auth/login.html'
    form_class = EmailAuthenticationForm
    redirect_authenticated_user = True

    def get_success_url(self):
        return self.get_redirect_url() or reverse_lazy('dashboard:home')

    def form_valid(self, form):
        messages.success(self.request, 'Welcome back.')
        return super().form_valid(form)


class AuthLogoutView(View):

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('authentication:login')
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return self._logout_and_redirect(request)

    def post(self, request, *args, **kwargs):
        return self._logout_and_redirect(request)

    def _logout_and_redirect(self, request):
        logout(request)
        messages.success(request, 'You are signed out.')
        return redirect('authentication:login')


class RegisterView(View):
    template_name = 'auth/register.html'
    form_class = RegistrationForm

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard:home')
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            user = form.save()
            raw_password = form.cleaned_data['password1']
            authenticated = authenticate(request, email=user.email, password=raw_password)
            if authenticated is not None:
                login(request, authenticated)
                messages.success(request, 'Account created. Lets get to work.')
                return redirect('dashboard:home')
            messages.info(request, 'Account created. Sign in to continue.')
            return redirect('authentication:login')
        return render(request, self.template_name, {'form': form})
