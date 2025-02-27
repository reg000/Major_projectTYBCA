from django.urls import path
from . import views
from .views import get_packets_api

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("start/", views.start_capture, name="start_capture"),
    path("stop/", views.stop_capture, name="stop_capture"),
    path('api/packets/', get_packets_api, name='get_packets_api'),
]
