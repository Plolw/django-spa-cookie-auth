from django.urls import path

from . import views

urlpatterns = [
    path('csrf/', views.get_csrf.as_view(), name='api-csrf'),
    path('login/', views.Login.as_view(), name='api-login'),
    path('logout/', views.Logout.as_view(), name='api-logout'),
    path('session/', views.session_view.as_view(), name='api-session'),
    path('whoami/', views.WhoAmI.as_view(), name='api-whoami')
]
