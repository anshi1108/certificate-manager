"""
URL configuration for certificate_manager project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

# urls.py
from django.urls import path
from certs import views  # Import views from the certs app


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.certificate_list, name='certificate_list'),
    path('upload/', views.certificate_upload, name='certificate_upload'),
    path('renew/<int:certificate_id>/', views.certificate_renew, name='certificate_renew'),
    path('certificate/<int:certificate_id>/', views.certificate_detail, name='certificate_detail')
    ]