from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<str:token>/', views.reset_password, name='reset_password'),
    path('logout/', views.logout, name='logout'),
    path('home/', views.home, name='home'),
    path('backend/', views.admin_page, name='backend_page'),  # Changed from admin to backend
    path('backend/manage-banner/', views.manage_banner, name='manage_banner'),
    path('backend/delete-banner/<int:id>/', views.delete_banner, name='delete_banner'),
    path('backend/manage-vision-mission/', views.manage_vision_mission, name='manage_vision_mission'),
    path('backend/delete-vision-mission/<int:id>/', views.delete_vision_mission, name='delete_vision_mission'),
    path('backend/manage-statistic/', views.manage_statistic, name='manage_statistic'),
    path('backend/delete-statistic/<int:id>/', views.delete_statistic, name='delete_statistic'),
    path('backend/manage-initiative/', views.manage_initiative, name='manage_initiative'),
    path('backend/delete-initiative/<int:id>/', views.delete_initiative, name='delete_initiative'),
]