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
        return self.email

class Banner(models.Model):
    id = models.AutoField(primary_key=True)
    image_url = models.CharField(max_length=255)  # Can be changed to ImageField for uploads
    title = models.CharField(max_length=150)
    description = models.TextField()
    order = models.IntegerField(default=0)
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class VisionMission(models.Model):
    id = models.AutoField(primary_key=True)
    vision_title = models.CharField(max_length=150)
    vision_description = models.CharField(max_length=200)
    mission_title = models.CharField(max_length=150)
    mission_description = models.CharField(max_length=200)
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.vision_title} & {self.mission_title}"

class Statistic(models.Model):
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )

    id = models.AutoField(primary_key=True)
    label = models.CharField(max_length=100)
    value = models.CharField(max_length=50)
    order = models.IntegerField(default=0)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.label

class Initiative(models.Model):
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )

    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=100)
    description = models.CharField(max_length=200)
    image_url = models.CharField(max_length=150)  # Can be changed to ImageField for uploads
    order = models.IntegerField(default=0)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title