from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.core.mail import send_mail
from .forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
from .models import User, Banner, VisionMission, Statistic, Initiative


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


def login(request):
    if 'user_id' in request.session:
        user = User.objects.get(user_id=request.session['user_id'])
        if user.role == 'admin':
            return redirect('backend_page')  # Changed from admin_page to backend_page
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
                        return redirect('backend_page')  # Changed from admin_page to backend_page
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
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            user.password_hash = make_password(form.cleaned_data['new_password'])
            user.reset_token = None
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


def logout(request):
    request.session.flush()
    messages.success(request, 'You have been logged out successfully.')
    return render(request, 'authapp/logout.html')


def admin_page(request):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    user = User.objects.get(user_id=request.session['user_id'])
    banners = Banner.objects.all().order_by('order')
    vision_missions = VisionMission.objects.all()
    statistics = Statistic.objects.all().order_by('order')
    initiatives = Initiative.objects.all().order_by('order')
    return render(request, 'authapp/backend_page.html', {  # Changed template name
        'user': user,
        'banners': banners,
        'vision_missions': vision_missions,
        'statistics': statistics,
        'initiatives': initiatives,
    })


def manage_banner(request):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    if request.method == 'POST':
        image_url = request.POST.get('image_url')
        title = request.POST.get('title')
        description = request.POST.get('description')
        order = request.POST.get('order', 0)
        status = request.POST.get('status') == 'on'
        if image_url and title and description:
            Banner.objects.create(
                image_url=image_url,
                title=title,
                description=description,
                order=int(order),
                status=status
            )
            messages.success(request, 'Banner added successfully.')
        else:
            messages.error(request, 'Please provide all required fields.')
        return redirect('backend_page')  # Changed from admin_page to backend_page
    return redirect('backend_page')

def delete_banner(request, id):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    banner = get_object_or_404(Banner, id=id)
    banner.delete()
    messages.success(request, 'Banner deleted successfully.')
    return redirect('backend_page')


def manage_vision_mission(request):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    if request.method == 'POST':
        vision_title = request.POST.get('vision_title')
        vision_description = request.POST.get('vision_description')
        mission_title = request.POST.get('mission_title')
        mission_description = request.POST.get('mission_description')
        if all([vision_title, vision_description, mission_title, mission_description]):
            VisionMission.objects.create(
                vision_title=vision_title,
                vision_description=vision_description,
                mission_title=mission_title,
                mission_description=mission_description
            )
            messages.success(request, 'Vision & Mission added successfully.')
        else:
            messages.error(request, 'Please provide all required fields.')
        return redirect('backend_page')  # Changed from admin_page to backend_page
    return redirect('backend_page')


def delete_vision_mission(request, id):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    vm = get_object_or_404(VisionMission, id=id)
    vm.delete()
    messages.success(request, 'Vision & Mission deleted successfully.')
    return redirect('backend_page')


def manage_statistic(request):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    if request.method == 'POST':
        label = request.POST.get('label')
        value = request.POST.get('value')
        order = request.POST.get('order', 0)
        status = request.POST.get('status', 'active')
        if label and value:
            Statistic.objects.create(
                label=label,
                value=value,
                order=int(order),
                status=status
            )
            messages.success(request, 'Statistic added successfully.')
        else:
            messages.error(request, 'Please provide all required fields.')
        return redirect('backend_page')  # Changed from admin_page to backend_page
    return redirect('backend_page')


def delete_statistic(request, id):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    stat = get_object_or_404(Statistic, id=id)
    stat.delete()
    messages.success(request, 'Statistic deleted successfully.')
    return redirect('backend_page')


def manage_initiative(request):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        image_url = request.POST.get('image_url')
        order = request.POST.get('order', 0)
        status = request.POST.get('status', 'active')
        if title and description and image_url:
            Initiative.objects.create(
                title=title,
                description=description,
                image_url=image_url,
                order=int(order),
                status=status
            )
            messages.success(request, 'Initiative added successfully.')
        else:
            messages.error(request, 'Please provide all required fields.')
        return redirect('backend_page')  # Changed from admin_page to backend_page
    return redirect('backend_page')


def delete_initiative(request, id):
    if 'user_id' not in request.session or request.session['role'] != 'admin':
        return redirect('login')

    initiative = get_object_or_404(Initiative, id=id)
    initiative.delete()
    messages.success(request, 'Initiative deleted successfully.')
    return redirect('backend_page')