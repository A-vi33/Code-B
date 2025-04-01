from django.urls import path
from . import views

urlpatterns = [
    # Frontend URLs
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('media/', views.media, name='media'),

    # Authentication URLs
    path('register/', views.register, name='register'),
    path('login/', views.login_page, name='login'),
    path('logout/', views.logout_page, name='logout'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<str:token>/', views.reset_password, name='reset_password'),

    # Backend Dashboard URLs
    path('backend/', views.backend_page, name='backend_page'),

    # Backend: Manage Banner URLs
    path('manage_banner/', views.manage_banner, name='manage_banner'),
    path('edit_banner/<int:id>/', views.edit_banner, name='edit_banner'),
    path('delete_banner/<int:banner_id>/', views.delete_banner, name='delete_banner'),

    # Backend: Manage Vision & Mission URLs
    path('manage_vision_mission/', views.manage_vision_mission, name='manage_vision_mission'),
    path('edit_vision_mission/<int:vision_mission_id>/', views.edit_vision_mission, name='edit_vision_mission'),
    path('delete_vision_mission/<int:vision_mission_id>/', views.delete_vision_mission, name='delete_vision_mission'),

    # Backend: Manage Statistics URLs
    path('manage_statistic/', views.manage_statistic, name='manage_statistic'),
    path('edit_statistic/<int:statistic_id>/', views.edit_statistic, name='edit_statistic'),
    path('delete_statistic/<int:statistic_id>/', views.delete_statistic, name='delete_statistic'),

    # Backend: Manage Initiatives URLs
    path('manage_initiative/', views.manage_initiative, name='manage_initiative'),
    path('edit_initiative/<int:initiative_id>/', views.edit_initiative, name='edit_initiative'),
    path('delete_initiative/<int:initiative_id>/', views.delete_initiative, name='delete_initiative'),

    # Backend: Manage About Us URLs
    path('manage_about_us/', views.manage_about_us, name='manage_about_us'),
    path('edit_about_us/<int:about_us_id>/', views.edit_about_us, name='edit_about_us'),
    path('delete_about_us/<int:about_us_id>/', views.delete_about_us, name='delete_about_us'),

    # Backend: Manage Team Members URLs
    path('manage_team_member/', views.manage_team_member, name='manage_team_member'),
    path('edit_team_member/<int:team_member_id>/', views.edit_team_member, name='edit_team_member'),
    path('delete_team_member/<int:team_member_id>/', views.delete_team_member, name='delete_team_member'),

    # Backend: Manage Projects URLs
    path('manage_projects/', views.manage_projects, name='manage_projects'),
    path('edit_project/<int:project_id>/', views.edit_project, name='edit_project'),
    path('delete_project/<int:project_id>/', views.delete_project, name='delete_project'),

    # Backend: Manage Media URLs
    path('manage-media/', views.manage_media, name='manage_media'),
    path('edit-press-release/<int:id>/', views.edit_press_release, name='edit_press_release'),
    path('delete-press-release/<int:id>/', views.delete_press_release, name='delete_press_release'),
    path('edit-video/<int:id>/', views.edit_video, name='edit_video'),
    path('delete-video/<int:id>/', views.delete_video, name='delete_video'),
    path('edit-image/<int:id>/', views.edit_image, name='edit_image'),
    path('delete-image/<int:id>/', views.delete_image, name='delete_image'),
    path('edit-media-coverage/<int:id>/', views.edit_media_coverage, name='edit_media_coverage'),
    path('delete-media-coverage/<int:id>/', views.delete_media_coverage, name='delete_media_coverage'),
    path('combined_dashboard/', views.combined_dashboard, name='combined_dashboard'),

    # Blog
    path('blog/', views.blog_list, name='blog_list'),
    path('manage-blog/', views.manage_blog, name='manage_blog'),
    path('edit-blog/<int:blog_id>/', views.edit_blog, name='edit_blog'),
    path('delete-blog/<int:blog_id>/', views.delete_blog, name='delete_blog'),
    path('donate/', views.donate, name='donate'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
]