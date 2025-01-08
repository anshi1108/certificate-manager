# urls.py
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from certs import views  # Make sure to import the views module

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.login_page, name='login_page'),
    path('cc_admin_dashboard/', views.cc_admin_dashboard, name='cc_admin_dashboard'),
    path('website_admin_dashboard/', views.website_admin_dashboard, name='website_admin_dashboard'),
    path('', views.certificate_list, name='certificate_list'),
    path('upload/', views.certificate_upload, name='certificate_upload'),
    path('renew/<int:certificate_id>/', views.certificate_renew, name='certificate_renew'),
    path('certificate/<int:certificate_id>/', views.certificate_detail, name='certificate_detail'),
]

# Serve media files in development (only works in DEBUG mode)
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
