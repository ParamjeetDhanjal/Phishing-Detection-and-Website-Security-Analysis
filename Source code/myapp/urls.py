from django.urls import path
from . import views

urlpatterns = [
    path('',views.phishing_site),
    path('url_website/',views.url_site),
    path('check_malicious/',views.check_url_view),
    path('phishing_info/',views.phished),
    path('website/',views.website_site),
    path('website_checker/',views.check_website_security)
]
