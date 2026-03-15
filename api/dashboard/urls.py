from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

app_name = 'dashboard'

router = DefaultRouter()
router.register(r'phishing-scans', views.PhishingScanViewSet, basename='phishing-scan')
router.register(r'document-analyses', views.DocumentAnalysisViewSet, basename='document-analysis')
router.register(r'behavior-events', views.BehaviorEventViewSet, basename='behavior-event')
router.register(r'malware-scans', views.MalwareScanViewSet, basename='malware-scan')
router.register(r'alerts', views.SecurityAlertViewSet, basename='security-alert')

urlpatterns = [
    path('', views.DashboardView.as_view(), name='home'),
    path('phishing/', views.phishing_view, name='phishing'),
    path('documents/', views.document_view, name='documents'),
    path('behavior/', views.behavior_view, name='behavior'),
    path('malware/', views.malware_view, name='malware'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('manifest.json', views.manifest_view, name='manifest'),
    path('offline/', views.offline_view, name='offline'),
    path('api/', include(router.urls)),
]

