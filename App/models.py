from django.db import models
import uuid
from django.utils import timezone
from datetime import timedelta

# Create your models here.
class User(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
    )
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )

    user_id = models.AutoField(primary_key=True)
    full_name = models.CharField(max_length=100, null=False)
    email = models.EmailField(max_length=100, unique=True, null=False)
    password_hash = models.CharField(max_length=255, null=False)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='user')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    reset_token = models.CharField(max_length=36, null=True, blank=True)  # UUID for reset
    token_expiry = models.DateTimeField(null=True, blank=True)  # Expiry for reset token
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  # Track updates

    def generate_reset_token(self):
        """Generate a reset token with a 1-hour expiry."""
        self.reset_token = str(uuid.uuid4())
        self.token_expiry = timezone.now() + timedelta(hours=1)  # Token expires in 1 hour
        self.save()
        return self.reset_token

    def is_reset_token_valid(self):
        """Check if the reset token is still valid."""
        if not self.reset_token or not self.token_expiry:
            return False
        return timezone.now() <= self.token_expiry

    def __str__(self):
        return self.full_name

class Banner(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    image_url = models.URLField(max_length=500, blank=True, null=True)
    order = models.IntegerField(default=0)
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class VisionMission(models.Model):
    vision_title = models.CharField(max_length=200)
    vision_description = models.TextField()
    mission_title = models.CharField(max_length=200)
    mission_description = models.TextField()
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.vision_title

class Statistic(models.Model):
    label = models.CharField(max_length=100)
    value = models.CharField(max_length=100)
    order = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=[('active', 'Active'), ('inactive', 'Inactive')], default='active')

    def __str__(self):
        return self.label

class Initiative(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    image_url = models.URLField(max_length=500, blank=True, null=True)
    order = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=[('active', 'Active'), ('inactive', 'Inactive')], default='active')

    def __str__(self):
        return self.title

class AboutUs(models.Model):
    introduction_title = models.CharField(max_length=200, blank=True)
    introduction_description = models.TextField(blank=True)
    mission_title = models.CharField(max_length=200, blank=True)
    mission_description = models.TextField(blank=True)
    vision_title = models.CharField(max_length=200, blank=True)
    vision_description = models.TextField(blank=True)
    history_title = models.CharField(max_length=200, blank=True)
    history_description = models.TextField(blank=True)
    milestones = models.TextField(blank=True)  # Store milestones as a newline-separated string
    core_values_title = models.CharField(max_length=200, blank=True)
    core_values = models.TextField(blank=True)  # Store core values as a newline-separated string
    programs_title = models.CharField(max_length=200, blank=True)
    programs = models.TextField(blank=True)  # Store programs as a newline-separated string
    team_title = models.CharField(max_length=200, blank=True)
    impact_title = models.CharField(max_length=200, blank=True)
    impact_description = models.TextField(blank=True)  # Store impact description and list
    cta_text = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_milestones_list(self):
        return self.milestones.splitlines() if self.milestones else []

    def get_core_values_list(self):
        return self.core_values.splitlines() if self.core_values else []

    def get_programs_list(self):
        return self.programs.splitlines() if self.programs else []

    def get_impact_list(self):
        # Extract the list items from impact_description (assuming the list starts after the first line)
        lines = self.impact_description.splitlines() if self.impact_description else []
        return lines[1:] if len(lines) > 1 else []

    def __str__(self):
        return f"About Us - {self.introduction_title}"

class TeamMember(models.Model):
    about_us = models.ForeignKey(AboutUs, on_delete=models.CASCADE, related_name='team_members')
    name = models.CharField(max_length=100)
    role = models.CharField(max_length=100)
    image = models.ImageField(upload_to='team_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Project(models.Model):
    STATUS_CHOICES = [
        ('ongoing', 'Ongoing'),
        ('completed', 'Completed'),
        ('upcoming', 'Upcoming'),
        ('active', 'Active'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ongoing')
    start_date = models.DateField(default='2023-01-01')
    end_date = models.DateField(blank=True, null=True)
    location = models.CharField(max_length=200, blank=True, null=True)
    image = models.ImageField(upload_to='projects/', blank=True, null=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class PressRelease(models.Model):
    title = models.CharField(max_length=200)
    date = models.DateField()
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class Video(models.Model):
    url = models.URLField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.url

class GalleryImage(models.Model):
    image = models.ImageField(upload_to='gallery/')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Image {self.id}"

class MediaCoverage(models.Model):
    title = models.CharField(max_length=200)
    url = models.URLField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class BlogPost(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    image = models.ImageField(upload_to='blog_images/', blank=True, null=True)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)  # New field
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_published = models.BooleanField(default=True)

    def __str__(self):
        return self.title

    class Meta:
        ordering = ['-created_at']

class Donation(models.Model):
    full_name = models.CharField(max_length=200)
    email = models.EmailField()
    phone_number = models.CharField(max_length=15)
    donation_amount = models.DecimalField(max_digits=10, decimal_places=2)
    blog_post = models.ForeignKey(BlogPost, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - ${self.donation_amount}"