from django import forms
from .models import User

class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    admin_code = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text="Enter the admin code if you have it."
    )

    class Meta:
        model = User
        fields = ['full_name', 'email', 'password']
        widgets = {
            'full_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")
        admin_code = cleaned_data.get("admin_code")
        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match")
        if admin_code and admin_code != "ADMIN2025":  # Replace with settings.ADMIN_CODE if using .env
            raise forms.ValidationError("Invalid admin code")
        return cleaned_data

class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control'}))

class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")
        if new_password != confirm_password:
            raise forms.ValidationError("Passwords do not match")
        return cleaned_data