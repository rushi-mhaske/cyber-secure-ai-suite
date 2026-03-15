from django.contrib import admin
from django.urls import path,include,re_path
from authentication.initials import create_default_profile
from django.conf import settings
from django.conf.urls.static import static
from django.db.models.signals import post_migrate
from authentication.views import Me, create_profile
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include(('authentication.urls', 'authentication'), namespace='authentication')),
    re_path(r'^auth/', include('djoser.urls')),
    re_path(r'^auth/', include('djoser.urls.authtoken')),
    path('create-profile/', create_profile),
    path('my-account/', Me.as_view()),
    path('', include('dashboard.urls')),
    path('api/', include(router.urls)),
]

if settings.DEBUG:
        urlpatterns += static(settings.STATIC_URL,document_root=settings.STATIC_ROOT)
        urlpatterns += static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)

post_migrate.connect(create_default_profile)