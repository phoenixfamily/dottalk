from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages

# صفحه ورود
def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            user = User.objects.get(email=email)
            user_auth = authenticate(username=user.username, password=password)
            if user_auth is not None:
                login(request, user_auth)
                messages.success(request, "خوش اومدی 🌟")
                return redirect("home")  # صفحه اصلی یا داشبورد
            else:
                messages.error(request, "ایمیل یا رمز عبور اشتباهه 😐")
        except User.DoesNotExist:
            messages.error(request, "کاربری با این ایمیل پیدا نشد 😕")

    return render(request, "login.html")


# صفحه ثبت‌نام
def register_view(request):
    if request.method == "POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        password = request.POST.get("password")
        password2 = request.POST.get("password2")

        if password != password2:
            messages.error(request, "رمزها با هم یکی نیستن 😅")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "ایمیل قبلاً ثبت شده 😐")
            return redirect("register")

        username = email.split("@")[0]
        user = User.objects.create_user(username=username, email=email, password=password)
        user.first_name = name
        user.save()

        messages.success(request, "ثبت‌نام موفقیت‌آمیز بود ✅")
        return redirect("login")

    return render(request, "register.html")


# خروج از حساب
def logout_view(request):
    logout(request)
    messages.info(request, "با موفقیت خارج شدی 👋")
    return redirect("login")
