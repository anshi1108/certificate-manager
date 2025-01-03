
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
    path('certificate/<int:certificate_id>/', views.certificate_detail, name='certificate_detail'),
    path('certificate/<int:certificate_id>/', views.certificate_detail, name='certificate_detail'),
    ]