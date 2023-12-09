import json

from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.views.decorators.http import require_POST
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework.authentication import SessionAuthentication

class get_csrf(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()

    def get(self, request):
        response = JsonResponse({'detail': 'CSRF cookie set'})
        response['X-CSRFToken'] = get_token(request)
        return response


class Login(APIView):
    permission_classes = (permissions.AllowAny,)

    @csrf_protect
    def post(self, request):
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        if username is None or password is None:
            return JsonResponse({'detail': 'Please provide username and password.'}, status=400)

        user = authenticate(username=username, password=password)

        if user is None:
            return JsonResponse({'detail': 'Invalid credentials.'}, status=400)

        login(request, user)
        return JsonResponse({'detail': 'Successfully logged in.'})

class Logout(APIView):
    @csrf_protect
    def post(self, request):
        logout(request)
        return JsonResponse({'detail': 'Successfully logged out.'})

class session_view(APIView):
    authentication_classes = ()
    permission_classes = (permissions.AllowAny,)

    @ensure_csrf_cookie
    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'isAuthenticated': False})

        return JsonResponse({'isAuthenticated': True})


class WhoAmI(APIView):
    authentication_classes = (SessionAuthentication,)

    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'isAuthenticated': False})

        return JsonResponse({'username': request.user.username})
