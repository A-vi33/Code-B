from django import forms
from .models import User, AboutUs, TeamMember
from .models import Banner, Statistic, Initiative, VisionMission, Project
from .models import PressRelease, Video, GalleryImage, MediaCoverage, BlogPost, Donation

class BannerForm(forms.ModelForm):
    class Meta:
        model = Banner
        fields = ['title', 'description', 'image_url', 'order', 'status']
        widgets = {
            'title': forms.TextInput(attrs={'required': 'required'}),
            'description': forms.Textarea(attrs={'required': 'required', 'rows': 4}),
            'image_url': forms.URLInput(attrs={'required': 'required'}),
            'order': forms.NumberInput(attrs={'value': '0'}),
            'status': forms.CheckboxInput(),
        }

class VisionMissionForm(forms.ModelForm):
    class Meta:
        model = VisionMission
        fields = ['vision_title', 'vision_description', 'mission_title', 'mission_description']
        widgets = {
            'vision_title': forms.TextInput(attrs={'required': 'required'}),
            'vision_description': forms.Textarea(attrs={'required': 'required', 'rows': 3}),
            'mission_title': forms.TextInput(attrs={'required': 'required'}),
            'mission_description': forms.Textarea(attrs={'required': 'required', 'rows': 3}),
        }

class StatisticForm(forms.ModelForm):
    class Meta:
        model = Statistic
        fields = ['label', 'value', 'order', 'status']
        widgets = {
            'label': forms.TextInput(attrs={'required': 'required'}),
            'value': forms.TextInput(attrs={'required': 'required'}),
            'order': forms.NumberInput(attrs={'value': '0'}),
            'status': forms.Select(choices=[('active', 'Active'), ('inactive', 'Inactive')]),
        }

class InitiativeForm(forms.ModelForm):
    class Meta:
        model = Initiative
        fields = ['title', 'description', 'image_url', 'order', 'status']
        widgets = {
            'title': forms.TextInput(attrs={'required': 'required'}),
            'description': forms.Textarea(attrs={'required': 'required', 'rows': 3}),
            'image_url': forms.URLInput(attrs={'required': 'required'}),
            'order': forms.NumberInput(attrs={'value': '0'}),
            'status': forms.Select(choices=[('active', 'Active'), ('inactive', 'Inactive')]),
        }

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

class AboutUsForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = [
            'introduction_title', 'introduction_description',
            'mission_title', 'mission_description',
            'vision_title', 'vision_description',
            'history_title', 'history_description', 'milestones',
            'core_values_title', 'core_values',
            'programs_title', 'programs',
            'team_title',
            'impact_title', 'impact_description',
            'cta_text'
        ]
        widgets = {
            'introduction_description': forms.Textarea(attrs={'rows': 3}),
            'mission_description': forms.Textarea(attrs={'rows': 3}),
            'vision_description': forms.Textarea(attrs={'rows': 3}),
            'history_description': forms.Textarea(attrs={'rows': 3}),
            'milestones': forms.Textarea(attrs={'rows': 4}),
            'core_values': forms.Textarea(attrs={'rows': 4}),
            'programs': forms.Textarea(attrs={'rows': 4}),
            'impact_description': forms.Textarea(attrs={'rows': 4}),
            'cta_text': forms.Textarea(attrs={'rows': 2}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make all fields optional
        for field in self.fields.values():
            field.required = False



class IntroductionForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = ['introduction_title', 'introduction_description']
        widgets = {
            'introduction_title': forms.TextInput(attrs={'class': 'form-control'}),
            'introduction_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

class MissionVisionForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = ['mission_title', 'mission_description', 'vision_title', 'vision_description']
        widgets = {
            'mission_title': forms.TextInput(attrs={'class': 'form-control'}),
            'mission_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'vision_title': forms.TextInput(attrs={'class': 'form-control'}),
            'vision_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

class HistoryForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = ['history_title', 'history_description', 'milestones']
        widgets = {
            'history_title': forms.TextInput(attrs={'class': 'form-control'}),
            'history_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'milestones': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

class CoreValuesForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = ['core_values_title', 'core_values']
        widgets = {
            'core_values_title': forms.TextInput(attrs={'class': 'form-control'}),
            'core_values': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

class ProgramsForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = ['programs_title', 'programs']
        widgets = {
            'programs_title': forms.TextInput(attrs={'class': 'form-control'}),
            'programs': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

class TeamTitleForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = ['team_title']
        widgets = {
            'team_title': forms.TextInput(attrs={'class': 'form-control'}),
        }

class ImpactForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = ['impact_title', 'impact_description']
        widgets = {
            'impact_title': forms.TextInput(attrs={'class': 'form-control'}),
            'impact_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        }

class CTAForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = ['cta_text']
        widgets = {
            'cta_text': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
        }

class TeamMemberForm(forms.ModelForm):
    class Meta:
        model = TeamMember
        fields = ['name', 'role', 'image']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'role': forms.TextInput(attrs={'class': 'form-control'}),
            'image': forms.FileInput(attrs={'class': 'form-control-file'}),
        }

class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['title', 'description', 'status', 'start_date', 'end_date', 'location', 'image']
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'end_date': forms.DateInput(attrs={'type': 'date'}),
        }

class PressReleaseForm(forms.ModelForm):
    class Meta:
        model = PressRelease
        fields = ['title', 'date', 'description']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
            'description': forms.Textarea(attrs={'rows': 3}),
        }

class VideoForm(forms.ModelForm):
    class Meta:
        model = Video
        fields = ['url']

class GalleryImageForm(forms.ModelForm):
    class Meta:
        model = GalleryImage
        fields = ['image']

class MediaCoverageForm(forms.ModelForm):
    class Meta:
        model = MediaCoverage
        fields = ['title', 'url']

class BlogPostForm(forms.ModelForm):
    class Meta:
        model = BlogPost
        fields = ['title', 'content', 'image', 'start_date', 'end_date', 'amount', 'is_published']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
            'image': forms.FileInput(attrs={'class': 'form-control'}),
            'start_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'end_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'is_published': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

class DonationForm(forms.ModelForm):
    class Meta:
        model = Donation
        fields = ['full_name', 'email', 'phone_number', 'donation_amount']
        widgets = {
            'full_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            'donation_amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
        }