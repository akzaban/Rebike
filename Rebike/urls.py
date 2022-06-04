"""Rebike URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
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
from app01 import views
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    #homepages
    path('homepage/', views.homepage),
    path('homepage_user/', views.homepage_user),
    #register and login
    path('register/', views.register),
    path('login/', views.login),
    path('logout/', views.logout),
    #index for different users
    path('index/', views.index),
    path('customer_index/', views.customer_index),
    path('operator_index/', views.operator_index),
    path('manager_index/', views.manager_index),
    #operator -- repair, delete and add bikes
    path('bike_manage_list/', views.bike_manage_list),
    path('bike_repair/', views.bike_repair),
    path('bike_delete/', views.bike_delete),
    path('bike_add/', views.bike_add),
    #user -- reset account information
    path('change_info/', views.change_info),
    path('reset_password/',views.reset_password),
    path('reset_email/',views.reset_email),
    path('retrieve_password/', views.retrieve_password),
    path('deal_repwd/',views.deal_repwd),
    path('deal_repwd_process/',views.deal_repwd_process),
    #manager -- add and delete operators
    path('operator_manage_list/',views.operator_manage_list),
    path('operator_add/', views.operator_add),
    path('operator_delete/',views.operator_delete),
      #track bike
    path('track_bike/', views.operators_track_bike),
    path('view_bike_info/',views.view_bike_info),
    #move bike
    path('move_bike/', views.operators_view_bikes_to_move),
    path('move_bike/<int:id>/', views.operator_move_bike,name='movebike'),
    #user rent and return bike
    path('step/', views.step1),
    path('input/<int:id>', views.input),
    path('return_car/', views.return_car),
    #manager
    path('bike_activites/',views.bike_activites,name='bike_activites'),
    path('Useractivites/',views.User_activites,name='Useractivites'),
    path('peaktime/',views.Peak_time,name='peaktime'),
    path('locations/',views.locations,name='locations'),
    #report defective bike
    path('defective/', views.defective),
    #customer payment and topup
    path('pay/', views.pay),
    path('topup/', views.topup),
    path('return_car/topup/', views.topup),
]+static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)