from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from certs import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.login_page, name='login_page'),  # Set login page as the root URL
    path('cc_admin_dashboard/', views.cc_admin_dashboard, name='cc_admin_dashboard'),
    path('website_admin_dashboard/', views.website_admin_dashboard, name='website_admin_dashboard'),
    path('certificates/', views.certificate_list, name='certificate_list'),  # Add prefix for certificates
    path('certificates/upload/', views.certificate_upload, name='certificate_upload'),
    path('certificates/renew/<int:certificate_id>/', views.certificate_renew, name='certificate_renew'),
    path('certificates/<int:certificate_id>/', views.certificate_detail, name='certificate_detail'),
]

# Serve media files in development (only works in DEBUG mode)
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
