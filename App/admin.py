from django.contrib import admin
from .models import Project
from .models import BlogPost
# Register your models here.

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('title', 'status', 'start_date', 'end_date', 'created_at')
    list_filter = ('status',)
    search_fields = ('title', 'description')

admin.site.register(BlogPost)