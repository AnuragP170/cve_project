"""
URL configuration for cve_project project.

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
from django.urls import path
from .views import update_page, update_cves, load_cve_data, load_ransomware_data

urlpatterns = [
    path('', load_cve_data, name='cve_list'),
    path('update/', update_page, name='update_page'),
    path('update-cves/', update_cves, name='update_cves'),
    path('ransomware/', load_ransomware_data, name='ransomware_cves')
]
