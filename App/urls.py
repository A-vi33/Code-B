# App/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('about/', views.about, name='about'),
    path('login/', views.login_page, name='login'),
    path('logout/', views.logout_page, name='logout'),
    path('backend/', views.backend_page, name='backend_page'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<str:token>/', views.reset_password, name='reset_password'),
    path('manage_banner/', views.manage_banner, name='manage_banner'),
    path('edit_banner/<int:id>/', views.edit_banner, name='edit_banner'),
    path('delete_banner/<int:banner_id>/', views.delete_banner, name='delete_banner'),
    path('manage_vision_mission/', views.manage_vision_mission, name='manage_vision_mission'),
    path('edit_vision_mission/<int:vision_mission_id>/', views.edit_vision_mission, name='edit_vision_mission'),
    path('delete_vision_mission/<int:vision_mission_id>/', views.delete_vision_mission, name='delete_vision_mission'),
    path('manage_statistic/', views.manage_statistic, name='manage_statistic'),
    path('edit_statistic/<int:statistic_id>/', views.edit_statistic, name='edit_statistic'),
    path('delete_statistic/<int:statistic_id>/', views.delete_statistic, name='delete_statistic'),
    path('manage_initiative/', views.manage_initiative, name='manage_initiative'),
    path('edit_initiative/<int:initiative_id>/', views.edit_initiative, name='edit_initiative'),
    path('delete_initiative/<int:initiative_id>/', views.delete_initiative, name='delete_initiative'),
    path('manage_about_us/', views.manage_about_us, name='manage_about_us'),
    path('edit_about_us/<int:about_us_id>/', views.edit_about_us, name='edit_about_us'),
    path('delete_about_us/<int:about_us_id>/', views.delete_about_us, name='delete_about_us'),
    path('manage_team_member/', views.manage_team_member, name='manage_team_member'),
    path('edit_team_member/<int:team_member_id>/', views.edit_team_member, name='edit_team_member'),
    path('delete_team_member/<int:team_member_id>/', views.delete_team_member, name='delete_team_member'),
]