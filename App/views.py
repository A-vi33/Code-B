# App/views.py
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from .forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
from django.shortcuts import render, redirect, get_object_or_404
from .models import User, Banner, VisionMission, Statistic, Initiative
from .forms import BannerForm, VisionMissionForm, StatisticForm, InitiativeForm, AboutUsForm
from .forms import (
    IntroductionForm, MissionVisionForm, HistoryForm, CoreValuesForm,
    ProgramsForm, TeamTitleForm, ImpactForm, CTAForm, TeamMemberForm
)
from .models import AboutUs, TeamMember
from django.contrib import messages
from functools import wraps

# Custom decorator to check if the user is logged in (based on session)
def session_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'user_id' not in request.session:
            messages.error(request, 'Please log in to access this page.')
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

# Custom decorator to check if the user is an admin (based on session role)
def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'user_id' not in request.session or request.session.get('role') != 'admin':
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('home')
        return view_func(request, *args, **kwargs)
    return wrapper

def index(request):
    if 'user_id' in request.session:
        return redirect('home')
    return redirect('login')

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.password_hash = make_password(form.cleaned_data['password'])
            if form.cleaned_data['admin_code'] == "ADMIN2025":
                if User.objects.filter(role='admin').exists():
                    messages.error(request, 'An Admin already exists!')
                    return redirect('register')
                user.role = 'admin'
            else:
                user.role = 'user'
            user.save()
            messages.success(request, 'Registration successful! Please log in.')
            return redirect('login')
    else:
        form = RegistrationForm()
    return render(request, 'authapp/signup.html', {'form': form})

def login_page(request):
    if 'user_id' in request.session:
        user = User.objects.get(user_id=request.session['user_id'])
        if user.role == 'admin':
            return redirect('backend_page')
        return redirect('home')
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            try:
                user = User.objects.get(email=email)
                if check_password(password, user.password_hash) and user.status == 'active':
                    request.session['user_id'] = str(user.user_id)
                    request.session['role'] = user.role
                    messages.success(request, 'Login successful!')
                    if user.role == 'admin':
                        return redirect('backend_page')
                    return redirect('home')
                else:
                    messages.error(request, 'Invalid credentials or inactive account.')
            except User.DoesNotExist:
                messages.error(request, 'User does not exist.')
    else:
        form = LoginForm()
    return render(request, 'authapp/login.html', {'form': form})

def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                token = user.generate_reset_token()
                reset_url = request.build_absolute_uri(f'/reset-password/{token}/')
                send_mail(
                    subject='Password Reset Request',
                    message=f'Click the link to reset your password: {reset_url}',
                    from_email='your-email@gmail.com',
                    recipient_list=[email],
                    fail_silently=False,
                )
                messages.success(request, 'A password reset link has been sent to your email.')
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, 'No user found with this email.')
            except Exception as e:
                messages.error(request, f'Failed to send email: {str(e)}')
    else:
        form = ForgotPasswordForm()
    return render(request, 'authapp/forgot_password.html', {'form': form})

def reset_password(request, token):
    user = get_object_or_404(User, reset_token=token)
    if not user.is_reset_token_valid():
        messages.error(request, 'The reset token has expired or is invalid.')
        return redirect('login')
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            user.password_hash = make_password(form.cleaned_data['new_password'])
            user.reset_token = None
            user.token_expiry = None
            user.save()
            messages.success(request, 'Password reset successful! Please log in.')
            return redirect('login')
    else:
        form = ResetPasswordForm()
    return render(request, 'authapp/reset_password.html', {'form': form, 'token': token})

def home(request):
    if 'user_id' not in request.session:
        return redirect('login')
    banners = Banner.objects.filter(status=True).order_by('order')
    vision_mission = VisionMission.objects.last()  # Get the latest vision & mission
    statistics = Statistic.objects.filter(status='active').order_by('order')
    initiatives = Initiative.objects.filter(status='active').order_by('order')
    return render(request, 'authapp/home.html', {
        'banners': banners,
        'vision_mission': vision_mission,
        'statistics': statistics,
        'initiatives': initiatives,
    })

def logout_page(request):
    request.session.flush()
    messages.success(request, 'You have been logged out successfully.')
    return render(request, 'authapp/logout.html')

@session_login_required
@admin_required
def backend_page(request):
    banners = Banner.objects.all()
    vision_missions = VisionMission.objects.all()
    statistics = Statistic.objects.all()
    initiatives = Initiative.objects.all()

    if request.method == 'POST':
        if 'banner_form' in request.POST:
            banner_form = BannerForm(request.POST)
            if banner_form.is_valid():
                banner_form.save()
                messages.success(request, 'Banner added successfully.')
                return redirect('backend_page')
            else:
                messages.error(request, 'Please correct the errors in the banner form.')
        elif 'vision_mission_form' in request.POST:
            vm_form = VisionMissionForm(request.POST)
            if vm_form.is_valid():
                vm_form.save()
                messages.success(request, 'Vision & Mission added successfully.')
                return redirect('backend_page')
            else:
                messages.error(request, 'Please correct the errors in the vision & mission form.')
        elif 'statistic_form' in request.POST:
            stat_form = StatisticForm(request.POST)
            if stat_form.is_valid():
                stat_form.save()
                messages.success(request, 'Statistic added successfully.')
                return redirect('backend_page')
            else:
                messages.error(request, 'Please correct the errors in the statistic form.')
        elif 'initiative_form' in request.POST:
            init_form = InitiativeForm(request.POST)
            if init_form.is_valid():
                init_form.save()
                messages.success(request, 'Initiative added successfully.')
                return redirect('backend_page')
            else:
                messages.error(request, 'Please correct the errors in the initiative form.')
    else:
        banner_form = BannerForm()
        vm_form = VisionMissionForm()
        stat_form = StatisticForm()
        init_form = InitiativeForm()

    return render(request, 'authapp/admin_page.html', {
        'banners': banners,
        'vision_missions': vision_missions,
        'statistics': statistics,
        'initiatives': initiatives,
        'banner_form': banner_form,
        'vm_form': vm_form,
        'stat_form': stat_form,
        'init_form': init_form,
    })

@session_login_required
@admin_required
def manage_banner(request):
    banners = Banner.objects.all()

    if request.method == 'POST':
        form = BannerForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Banner added successfully.')
            return redirect('manage_banner')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = BannerForm()

    return render(request, 'authapp/manage_banner.html', {
        'form': form,
        'banners': banners,
    })

@session_login_required
@admin_required
def edit_banner(request, id):
    banner = get_object_or_404(Banner, id=id)

    if request.method == 'POST':
        form = BannerForm(request.POST, instance=banner)
        if form.is_valid():
            form.save()
            messages.success(request, 'Banner updated successfully.')
            return redirect('manage_banner')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = BannerForm(instance=banner)

    return render(request, 'authapp/edit_banner.html', {'form': form, 'banner': banner})

@session_login_required
@admin_required
def delete_banner(request, banner_id):
    banner = get_object_or_404(Banner, id=banner_id)

    if request.method == 'POST':
        referer = request.META.get('HTTP_REFERER', '')
        if 'manage_banner' not in referer and 'backend' not in referer:
            messages.error(request, 'Invalid deletion request. Please use the manage banner or admin page.')
            return redirect('manage_banner')

        try:
            banner.delete()
            messages.success(request, 'Banner deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting banner: {str(e)}')

        # Redirect back to the page the user came from
        if 'backend' in referer:
            return redirect('backend_page')
        return redirect('manage_banner')
    else:
        messages.error(request, 'Please use the delete button to remove a banner.')
        return redirect('manage_banner')

@session_login_required
@admin_required
def manage_vision_mission(request):
    if request.method == 'POST':
        form = VisionMissionForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Vision & Mission added successfully.')
            return redirect('backend_page')
        else:
            messages.error(request, 'Please correct the errors below.')
    return redirect('backend_page')

@session_login_required
@admin_required
def edit_vision_mission(request, vision_mission_id):  # Change 'id' to 'vision_mission_id'
    vm = get_object_or_404(VisionMission, id=vision_mission_id)
    if request.method == 'POST':
        form = VisionMissionForm(request.POST, instance=vm)
        if form.is_valid():
            form.save()
            messages.success(request, 'Vision & Mission updated successfully.')
            return redirect('backend_page')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = VisionMissionForm(instance=vm)
    return render(request, 'authapp/edit_vision_mission.html', {'form': form, 'vision_mission': vm})

@session_login_required
@admin_required
def delete_vision_mission(request, vision_mission_id):
    vm = get_object_or_404(VisionMission, id=vision_mission_id)
    if request.method == 'POST':
        referer = request.META.get('HTTP_REFERER', '')
        if 'backend' not in referer:
            messages.error(request, 'Invalid deletion request. Please use the admin page to delete a vision & mission.')
            return redirect('backend_page')

        vm.delete()
        messages.success(request, 'Vision & Mission deleted successfully.')
        return redirect('backend_page')
    else:
        messages.error(request, 'Please use the delete button to remove a vision & mission.')
        return redirect('backend_page')

@session_login_required
@admin_required
def manage_statistic(request):
    if request.method == 'POST':
        form = StatisticForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Statistic added successfully.')
            return redirect('backend_page')
        else:
            messages.error(request, 'Please correct the errors below.')
    return redirect('backend_page')

@session_login_required
@admin_required
def edit_statistic(request, statistic_id):
    stat = get_object_or_404(Statistic, id=statistic_id)
    if request.method == 'POST':
        form = StatisticForm(request.POST, instance=stat)
        if form.is_valid():
            form.save()
            messages.success(request, 'Statistic updated successfully.')
            return redirect('backend_page')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = StatisticForm(instance=stat)  # Render the form for GET requests
    return render(request, 'authapp/edit_statistic.html', {'form': form, 'statistic': stat})

@session_login_required
@admin_required
def delete_statistic(request, statistic_id):
    stat = get_object_or_404(Statistic, id=statistic_id)
    if request.method == 'POST':
        referer = request.META.get('HTTP_REFERER', '')
        if 'backend' not in referer:
            messages.error(request, 'Invalid deletion request. Please use the admin page to delete a statistic.')
            return redirect('backend_page')

        stat.delete()
        messages.success(request, 'Statistic deleted successfully.')
        return redirect('backend_page')
    else:
        messages.error(request, 'Please use the delete button to remove a statistic.')
        return redirect('backend_page')

@session_login_required
@admin_required
def manage_initiative(request):
    if request.method == 'POST':
        form = InitiativeForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Initiative added successfully.')
            return redirect('backend_page')
        else:
            messages.error(request, 'Please correct the errors below.')
    return redirect('backend_page')

@session_login_required
@admin_required
def edit_initiative(request, initiative_id):  # Change 'id' to 'initiative_id'
    initiative = get_object_or_404(Initiative, id=initiative_id)
    if request.method == 'POST':
        form = InitiativeForm(request.POST, instance=initiative)
        if form.is_valid():
            form.save()
            messages.success(request, 'Initiative updated successfully.')
            return redirect('backend_page')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = InitiativeForm(instance=initiative)
    return render(request, 'authapp/edit_initiative.html', {'form': form, 'initiative': initiative})

@session_login_required
@admin_required
def delete_initiative(request, initiative_id):
    initiative = get_object_or_404(Initiative, id=initiative_id)
    if request.method == 'POST':
        referer = request.META.get('HTTP_REFERER', '')
        if 'backend' not in referer:
            messages.error(request, 'Invalid deletion request. Please use the admin page to delete an initiative.')
            return redirect('backend_page')

        initiative.delete()
        messages.success(request, 'Initiative deleted successfully.')
        return redirect('backend_page')
    else:
        messages.error(request, 'Please use the delete button to remove an initiative.')
        return redirect('backend_page')

def about(request):
    about_us = AboutUs.objects.last()  # Get the latest About Us content
    if not about_us:
        about_us = AboutUs.objects.create(
            introduction_title="Welcome to [NGO Name]",
            introduction_description="We are a passionate team dedicated to making a difference in the lives of underprivileged communities through education, healthcare, and empowerment.",
            mission_title="Our Mission",
            mission_description="To provide quality education to every child, regardless of their socio-economic background.",
            vision_title="Our Vision",
            vision_description="A world where every individual has the opportunity to live with dignity and purpose.",
            history_title="Our Story",
            history_description="Founded in 2015, [NGO Name] started as a small community initiative. Today, we have empowered over 10,000 individuals across 50+ villages.",
            milestones="2018: Launched our first school.\n2020: Organized 100+ health camps in rural areas.\n2022: Reached the milestone of 10,000 beneficiaries.",
            core_values_title="Our Core Values",
            core_values="Integrity\nEmpathy\nInclusivity\nTransparency",
            programs_title="Our Programs",
            programs="Providing free educational resources for children.\nRunning health camps for rural areas.\nOffering vocational training for women.",
            team_title="Meet Our Team",
            impact_title="Our Impact",
            impact_description="In the past year, we have achieved:\nEducated over 5,000 children.\nConducted 50+ health camps.\nEmpowered 200 women with vocational training.",
            cta_text="Become a part of the change. Volunteer today or donate to help transform lives."
        )
    return render(request, 'authapp/about.html', {
        'about_us': about_us,
    })

@session_login_required
@admin_required
def manage_about_us(request):
    about_us = AboutUs.objects.first()  # Get the latest About Us content
    if not about_us:
        about_us = AboutUs.objects.create()

    introduction_form = IntroductionForm(instance=about_us)
    mission_vision_form = MissionVisionForm(instance=about_us)
    history_form = HistoryForm(instance=about_us)
    core_values_form = CoreValuesForm(instance=about_us)
    programs_form = ProgramsForm(instance=about_us)
    team_title_form = TeamTitleForm(instance=about_us)
    impact_form = ImpactForm(instance=about_us)
    cta_form = CTAForm(instance=about_us)
    team_member_form = TeamMemberForm()

    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'introduction':
            introduction_form = IntroductionForm(request.POST, instance=about_us)
            if introduction_form.is_valid():
                introduction_form.save()
                messages.success(request, "Introduction updated successfully!")
                return redirect('manage_about_us')
            else:
                messages.error(request, "Error saving Introduction. Please check the fields below.")
                print("IntroductionForm errors:", introduction_form.errors)

        elif form_type == 'mission_vision':
            mission_vision_form = MissionVisionForm(request.POST, instance=about_us)
            if mission_vision_form.is_valid():
                mission_vision_form.save()
                messages.success(request, "Mission and Vision updated successfully!")
                return redirect('manage_about_us')
            else:
                messages.error(request, "Error saving Mission and Vision. Please check the fields below.")
                print("MissionVisionForm errors:", mission_vision_form.errors)

        elif form_type == 'history':
            history_form = HistoryForm(request.POST, instance=about_us)
            if history_form.is_valid():
                history_form.save()
                messages.success(request, "Our Story updated successfully!")
                return redirect('manage_about_us')
            else:
                messages.error(request, "Error saving Our Story. Please check the fields below.")
                print("HistoryForm errors:", history_form.errors)

        elif form_type == 'core_values':
            core_values_form = CoreValuesForm(request.POST, instance=about_us)
            if core_values_form.is_valid():
                core_values_form.save()
                messages.success(request, "Core Values updated successfully!")
                return redirect('manage_about_us')
            else:
                messages.error(request, "Error saving Core Values. Please check the fields below.")
                print("CoreValuesForm errors:", core_values_form.errors)

        elif form_type == 'programs':
            programs_form = ProgramsForm(request.POST, instance=about_us)
            if programs_form.is_valid():
                programs_form.save()
                messages.success(request, "Programs updated successfully!")
                return redirect('manage_about_us')
            else:
                messages.error(request, "Error saving Programs. Please check the fields below.")
                print("ProgramsForm errors:", programs_form.errors)

        elif form_type == 'team_title':
            team_title_form = TeamTitleForm(request.POST, instance=about_us)
            if team_title_form.is_valid():
                team_title_form.save()
                messages.success(request, "Team Title updated successfully!")
                return redirect('manage_about_us')
            else:
                messages.error(request, "Error saving Team Title. Please check the fields below.")
                print("TeamTitleForm errors:", team_title_form.errors)

        elif form_type == 'impact':
            impact_form = ImpactForm(request.POST, instance=about_us)
            if impact_form.is_valid():
                impact_form.save()
                messages.success(request, "Impact updated successfully!")
                return redirect('manage_about_us')
            else:
                messages.error(request, "Error saving Impact. Please check the fields below.")
                print("ImpactForm errors:", impact_form.errors)

        elif form_type == 'cta':
            cta_form = CTAForm(request.POST, instance=about_us)
            if cta_form.is_valid():
                cta_form.save()
                messages.success(request, "Call to Action updated successfully!")
                return redirect('manage_about_us')
            else:
                messages.error(request, "Error saving Call to Action. Please check the fields below.")
                print("CTAForm errors:", cta_form.errors)

    return render(request, 'authapp/manage_about_us.html', {
        'about_us': about_us,
        'introduction_form': introduction_form,
        'mission_vision_form': mission_vision_form,
        'history_form': history_form,
        'core_values_form': core_values_form,
        'programs_form': programs_form,
        'team_title_form': team_title_form,
        'impact_form': impact_form,
        'cta_form': cta_form,
        'team_member_form': team_member_form,
    })

@session_login_required
@admin_required
def edit_about_us(request, about_us_id):
    about_us = get_object_or_404(AboutUs, id=about_us_id)
    if request.method == 'POST':
        form = AboutUsForm(request.POST, instance=about_us)
        if form.is_valid():
            form.save()
            messages.success(request, "About Us content updated successfully!")
            return redirect('manage_about_us')
    else:
        form = AboutUsForm(instance=about_us)
    return render(request, 'authapp/edit_about_us.html', {
        'about_us': about_us,
        'about_us_form': form,
    })

@session_login_required
@admin_required
def delete_about_us(request, about_us_id):
    about_us = get_object_or_404(AboutUs, id=about_us_id)
    about_us.delete()
    messages.success(request, "About Us content deleted successfully!")
    return redirect('manage_about_us')

@session_login_required
@admin_required
def manage_team_member(request):
    about_us = AboutUs.objects.last()
    if not about_us:
        about_us = AboutUs.objects.create()

    if request.method == 'POST':
        team_member_form = TeamMemberForm(request.POST, request.FILES)
        if team_member_form.is_valid():
            team_member = team_member_form.save(commit=False)
            team_member.about_us = about_us
            team_member.save()
            messages.success(request, "Team member added successfully!")
            return redirect('manage_about_us')
        else:
            messages.error(request, "Error adding team member. Please check the fields below.")
            print("TeamMemberForm errors:", team_member_form.errors)

    return redirect('manage_about_us')

@session_login_required
@admin_required
def edit_team_member(request, team_member_id):
    team_member = get_object_or_404(TeamMember, id=team_member_id)
    if request.method == 'POST':
        form = TeamMemberForm(request.POST, request.FILES, instance=team_member)
        if form.is_valid():
            form.save()
            messages.success(request, "Team member updated successfully!")
            return redirect('manage_about_us')
    else:
        form = TeamMemberForm(instance=team_member)
    return render(request, 'authapp/edit_team_member.html', {
        'team_member': team_member,
        'team_member_form': form,
    })

@session_login_required
@admin_required
def delete_team_member(request, team_member_id):
    team_member = get_object_or_404(TeamMember, id=team_member_id)
    team_member.delete()
    messages.success(request, "Team member deleted successfully!")
    return redirect('manage_about_us')