from django.urls import path
from . import views

app_name = "accounts-api-v1"

urlpatterns = [
    path('register/', views.CreateUserView.as_view(), name='register'),
    path('login/', views.CreateTokenView.as_view(), name='login'),
    path('update/', views.ManageUserView.as_view(), name='update'),
]