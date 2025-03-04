from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from certs import views

urlpatterns = [
    path('website_admin_dashboard/', views.website_admin_dashboard, name='website_admin_dashboard'),
    path('cc_admin_dashboard/', views.cc_admin_dashboard, name='cc_admin_dashboard'),
    path('cc_admin_users/', views.cc_admin_users, name='cc_admin_users'),
    path('add_user/', views.add_user, name='add_user'),
    path('edit_user/<str:username>/', views.edit_user, name='edit_user'),
    path('delete_user/<str:username>/', views.delete_user, name='delete_user'),
    path('admin/', admin.site.urls),  # Admin routes
    path ('cc_admin_main/',views.cc_admin_main_view,name="cc_admin_main_view"),
    # Certificate Management
    path('certificates/', views.certificate_list, name='certificate_list'),
    path('certificates/upload/', views.certificate_upload, name='certificate_upload'),
    path('certificates/renew/<int:certificate_id>/', views.certificate_renew, name='certificate_renew'),
    path('certificates/<int:certificate_id>/', views.certificate_detail, name='certificate_detail'),
    path('certificates/<int:certificate_id>/download/<str:file_type>/', views.download_file, name='download_file'),
    path('certificate/delete/<int:certificate_id>/', views.certificate_delete, name='certificate_delete'),
    path('user/<str:username>/certificates/', views.user_certificates, name='user_certificates'),
    path('your-certificate-list/', views.certificate_list, name='your_certificate_list_url'),
    
    # SSO Authentication (Fixed `auth` to `sso_callback`)
    path('', views.sso_login, name='home'),  # Redirects to IITB SSO by default
    path('sso_callback/', views.sso_callback, name='sso_callback'),  # Fixed view name
    path('logout/', views.logout, name='logout'),
]

# Serve media files in development (only works in DEBUG mode)
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
