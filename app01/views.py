from django.shortcuts import render, redirect
from app01 import models
from functools import wraps
from django.contrib.auth.hashers import make_password, check_password
import random, string
from django.db.models.functions import Length
from datetime import date, datetime, time
from django.contrib import messages
from django.db.models import Count
from pathlib import Path
from django_pandas.io import read_frame
from .models import Rentdetails, Report
from matplotlib import pyplot as plt
import pandas as pdf
import matplotlib
import decimal
import os
from os import path
from django.core.mail import send_mail
import numpy as np

"""
To get userid:
# is_login = request.get_signed_cookie('is_login', salt='s7', default='')
# userid = int(is_login[1:])
"""


######################################################################################## Xu Wang ####################################################################################################################


# Create your views here.

# check login status with cookie
def login_required(func):
    @wraps(func)
    def inner(request, *args, **kwargs):
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        if not is_login:
            return redirect('/login/')
        ret = func(request, *args, **kwargs)
        return ret

    return inner


def customer_required(func):
    @wraps(func)
    def inner(request, *args, **kwargs):
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        if not is_login:
            return redirect('/login/')
        if is_login[0] == 'o':
            return redirect('/operator_index/')
        if is_login[0] == 'm':
            return redirect('/manager_index/')
        ret = func(request, *args, **kwargs)
        return ret

    return inner


def operator_required(func):
    @wraps(func)
    def inner(request, *args, **kwargs):
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        if not is_login:
            return redirect('/login/')
        if is_login[0] == 'c':
            return redirect('/customer_index/')
        if is_login[0] == 'm':
            return redirect('/manager_index/')
        ret = func(request, *args, **kwargs)
        return ret

    return inner


def manager_required(func):
    @wraps(func)
    def inner(request, *args, **kwargs):
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        if not is_login:
            return redirect('/login/')
        if is_login[0] == 'c':
            return redirect('/customer_index/')
        if is_login[0] == 'o':
            return redirect('/operator_index/')
        ret = func(request, *args, **kwargs)
        return ret

    return inner


# homepage for tourists
def homepage(request):
    return render(request, 'homepage.html')


# homepage for users
@login_required
def homepage_user(request):
    return render(request, 'homepage_user.html')


# register
def register(request):
    if request.method == 'POST':
        user = request.POST.get('user')
        pwd = request.POST.get('pwd')
        pwdagain = request.POST.get('pwdagain')
        email = request.POST.get('email')
        postcode = request.POST.get('postcode')
        if postcode:
            postcode = postcode.replace(" ", "")
        if user and pwd and pwdagain and email:
            if models.User.objects.filter(username=user).count() > 0:
                error = "The username already exists."
                return render(request, 'register.html', locals())
            elif models.User.objects.filter(email=email).count() > 0:
                error = "The email already exists."
                return render(request, 'register.html', locals())
            else:
                if (pwd == pwdagain):
                    if postcode:
                        if len(postcode) != 5 and len(postcode) != 6:
                            error = "Wrong postcode."
                            return render(request, 'register.html', locals())
                        if postcode[0] != 'G':
                            error = "ReBike is only for Glasgow now. Please check the postcode"
                            return render(request, 'register.html', locals())
                    use = models.User(username=user, password=make_password(pwd), amount=0, group=0, postcode=postcode,
                                      email=email)
                    use.save()
                    # message = "Successful registration."
                    return redirect('/login/')
                else:
                    error = "The passwords entered did not match."
                    return render(request, 'register.html', locals())
        else:
            error = "Please fill in the form."
            return render(request, 'register.html', locals())
    else:
        return render(request, 'register.html')


# login
def login(request):
    if request.method == 'POST':
        user = request.POST.get('user')
        pwd = request.POST.get('pwd')
        if user and pwd:
            if models.User.objects.filter(username=user).count() == 1:
                user_obj = models.User.objects.get(username=user)
                if check_password(pwd, user_obj.password):
                    if user_obj.group == 0:
                        ret = redirect('/customer_index/')
                        ret.set_signed_cookie('is_login', 'c' + str(user_obj.userid), salt='s7')
                    elif user_obj.group == 1:
                        ret = redirect('/operator_index/')
                        ret.set_signed_cookie('is_login', 'o' + str(user_obj.userid), salt='s7')
                    elif user_obj.group == 2:
                        ret = redirect('/manager_index/')
                        ret.set_signed_cookie('is_login', 'm' + str(user_obj.userid), salt='s7')
                    else:
                        error = 'Wrong user information, please contact the administrator.'
                        return render(request, 'login.html', locals())
                    return ret
                else:
                    error = 'Wrong password.'
                    return render(request, 'login.html', locals())
            else:
                error = 'Username does not exist.'
                return render(request, 'login.html', locals())
        else:
            error = 'Please enter username and password.'
            return render(request, 'login.html', locals())
    return render(request, 'login.html')


# logout
@login_required
def logout(request):
    ret = redirect('/login')
    ret.delete_cookie('is_login')
    return ret


# change information(password, email)
@login_required
def change_info(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    if user_obj.group == 0:
        return render(request, 'customer_change_info.html', locals())
    elif user_obj.group == 1:
        return render(request, 'operator_change_info.html', locals())
    else:
        return render(request, 'manager_change_info.html', locals())


# reset password
@login_required
def reset_password(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    if request.method == 'POST':
        pwd = request.POST.get('pwd')
        new_pwd = request.POST.get('new_pwd')
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        userid = int(is_login[1:])
        user_obj = models.User.objects.get(userid=userid)
        if check_password(pwd, user_obj.password):
            user_obj.password = make_password(new_pwd)
            user_obj.save()
            message = 'Changed successfully.'
        else:
            error = 'The current password you have typed is wrong.'
        if user_obj.group == 0:
            return render(request, 'customer_reset_password.html', locals())
        elif user_obj.group == 1:
            return render(request, 'operator_reset_password.html', locals())
        else:
            return render(request, 'manager_reset_password.html', locals())
    if user_obj.group == 0:
        return render(request, 'customer_reset_password.html', locals())
    elif user_obj.group == 1:
        return render(request, 'operator_reset_password.html', locals())
    else:
        return render(request, 'manager_reset_password.html', locals())


# reset email address
@login_required
def reset_email(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    message = ''
    error = ''
    if request.method == 'POST':
        new_email = request.POST.get('new_email')
        if models.User.objects.filter(email=new_email).count() == 0:
            is_login = request.get_signed_cookie('is_login', salt='s7', default='')
            userid = int(is_login[1:])
            user_obj = models.User.objects.get(userid=userid)
            user_obj.email = new_email
            user_obj.save()
            message = 'Changed successfully.'
        else:
            error = 'The email exists.'
        if user_obj.group == 0:
            return render(request, 'customer_reset_email.html', locals())
        elif user_obj.group == 1:
            return render(request, 'operator_reset_email.html', locals())
        else:
            return render(request, 'manager_reset_email.html', locals())
    if user_obj.group == 0:
        return render(request, 'customer_reset_email.html', locals())
    elif user_obj.group == 1:
        return render(request, 'operator_reset_email.html', locals())
    else:
        return render(request, 'manager_reset_email.html', locals())


# retrieve password
def retrieve_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if models.User.objects.filter(email=email).count() > 0:
            user = models.User.objects.get(email=email)
            models.Repwd_Request.objects.create(email=email, ifdeal=False)
            message = 'The administrator will send an email with a temporary password.'
            return render(request, 'retrieve_password.html', locals())
        else:
            error = 'The email does not exist.'
            return render(request, 'retrieve_password.html', locals())
    return render(request, 'retrieve_password.html')


# help user retrieve password - show the request list
@operator_required
def deal_repwd(request):
    all_requests = models.Repwd_Request.objects.filter(ifdeal=0).order_by('requesttime')
    return render(request, 'deal_repwd.html', locals())


# help user retrieve password - generate a temporary password
@operator_required
def deal_repwd_process(request):
    pk = request.GET.get('pk')
    repwd_request = models.Repwd_Request.objects.get(requestid=pk)
    email = repwd_request.email
    user = models.User.objects.get(email=email)
    newpwd = ''.join(random.sample(string.ascii_letters + string.digits, 6))
    user.password = make_password(newpwd)
    user.save()
    repwd_request.ifdeal = True
    repwd_request.save()
    return render(request, 'deal_repwd_finished.html', locals())


# index for customer
@customer_required
def customer_index(request):
    return render(request, 'customer_index.html')


# index for operator
@operator_required
def operator_index(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    username = user_obj.username
    return render(request, 'operator_index.html', {'username': username})


# index for manager
@manager_required
def manager_index(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    username = user_obj.username
    return render(request, 'manager_index.html', {'username': username})


# operator -- bike list
@operator_required
def bike_manage_list(request):
    if request.method == 'POST':
        bikeid = request.POST.get('bikeid')
        if bikeid:
            if models.Bike.objects.filter(bikeid=bikeid).count() == 1:
                bike_obj = models.Bike.objects.get(bikeid=bikeid)
                return render(request, 'bike_manage_specific.html', locals())
            else:
                error = 'The bikeid does not exist.'
                all_bikes = models.Bike.objects.all().order_by('bikeid')
                return render(request, 'bike_manage_list.html', locals())
        else:
            all_bikes = models.Bike.objects.all().order_by('bikeid')
            return render(request, 'bike_manage_list.html', locals())
    else:
        all_bikes = models.Bike.objects.all().order_by('bikeid')
        return render(request, 'bike_manage_list.html', locals())


# operator -- repair a bike
@operator_required
def bike_repair(request):
    pk = request.GET.get('pk')
    bike_obj = models.Bike.objects.get(bikeid=pk)
    if bike_obj:
        if bike_obj.ifdefective == 1:
            bike_obj.ifdefective = 0
            bike_obj.defective_details = None
            bike_obj.save()
        else:
            # error = 'The bike does not need repair.'
            return redirect('/bike_manage_list/')
    else:
        # error = 'Bikeid does not exist.'
        return redirect('/bike_manage_list/')
    return redirect('/bike_manage_list/')


# operator -- delete a bike
@operator_required
def bike_delete(request):
    pk = request.GET.get('pk')
    bike_obj = models.Bike.objects.filter(bikeid=pk)
    models.Bike.objects.filter(bikeid=pk).update(station=None)
    bike_obj.delete()
    return redirect('/bike_manage_list/')


# operator -- add a bike
@operator_required
def bike_add(request):
    if request.method == 'POST':
        postcode = request.POST.get('postcode').replace(" ", "")
        stationid = request.POST.get('stationid')
        if len(postcode) != 5 and len(postcode) != 6:
            error = "Wrong postcode."
            return render(request, 'bike_add.html', locals())
        if postcode[0] != 'G':
            error = "ReBike is only for Glasgow now. Please check the postcode"
            return render(request, 'bike_add.html', locals())
        if stationid:
            if models.Station.objects.filter(stationid=stationid).exists():
                station = models.Station.objects.filter(stationid=stationid)
                postcode = station[0].postcode
                models.Bike.objects.create(postcode=postcode, ifdefective=0, ifavailable=1, ifstation=1,
                                           station_id=stationid, defective_details=None, postcode_len=len(postcode))
                message = 'Added successfully.'
            else:
                error = 'The station does not exist.'
                return render(request, 'bike_add.html', locals())
        else:
            models.Bike.objects.create(postcode=postcode, ifdefective=0, ifavailable=1, ifstation=0,
                                       station_id=None, defective_details=None, postcode_len=len(postcode))
            message = 'Added successfully.'
        return render(request, 'bike_add.html', locals())
    else:
        return render(request, 'bike_add.html')


# manager -- operator list
@manager_required
def operator_manage_list(request):
    all_operators = models.User.objects.filter(group=1).order_by('userid')
    return render(request, 'operator_manage_list.html', locals())


# manager -- add an operator with default password '123456'
@manager_required
def operator_add(request):
    if request.method == 'POST':
        user = request.POST.get('user')
        email = request.POST.get('email')
        postcode = request.POST.get('postcode').replace(" ","")
        if user and email and postcode:
            if len(postcode) != 5 and len(postcode) != 6:
                error = "Wrong postcode."
                return render(request, 'bike_add.html', locals())
            if postcode[0] != 'G':
                error = "ReBike is only for Glasgow now. Please check the postcode"
                return render(request, 'bike_add.html', locals())
            if models.User.objects.filter(username=user).count() > 0:
                error = "The username already exists."
                return render(request, 'operator_add.html', locals())
            if models.User.objects.filter(email=email).count() > 0:
                error = "The email already exists."
                return render(request, 'operator_add.html', locals())
            use = models.User(username=user, password=make_password('123456'), amount=0, group=1, postcode=postcode,
                              email=email)
            use.save()
            message = "Successful."
            return render(request, 'operator_add.html', locals())
        else:
            error = "Please fill in the form."
            return render(request, 'operator_add.html', locals())
    return render(request, 'operator_add.html')


# manager -- delete an operator
@manager_required
def operator_delete(request):
    pk = request.GET.get('pk')
    user_obj = models.User.objects.filter(userid=pk)
    user_obj.delete()
    return redirect('/operator_manage_list/')


# homepage navigate to personal index
@login_required
def index(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    if user_obj.group == 0:
        return redirect('/customer_index/')
    elif user_obj.group == 1:
        return redirect('/operator_index/')
    else:
        return redirect('/manager_index/')


######################################################################################## Eleftheria ####################################################################################################################

# operator -- track bike
@operator_required
def operators_track_bike(request):
    if request.method == "GET":
        bike = models.Bike.objects.all()
        return render(request, 'trackbike.html', {"id": id, "bike": bike,})
    else:
        bike = request.POST.get('bike')
        if bike == "select bike to track":
            bike = models.Bike.objects.all()
            return render(request, 'trackbike.html', {"id": id, "bike": bike,})
        bike_obj = models.Bike.objects.filter(bikeid = bike)
        
        return render(request, 'bikeinfo.html',{'current_bike': bike_obj} )


# views bike info after tracking bike
def view_bike_info(request):
    return render(request, 'bikeinfo.html')


# page where operator can view bikes that need to be moved - returns operators-movebike.html template
@operator_required
def operators_view_bikes_to_move(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    current_operator = models.User.objects.filter(userid=userid)
    # current_operator = models.User.objects.filter(username = "operator",group=1) #need to get currently logged in operator
    current_operators_location = current_operator[0].postcode  # need current operator's postcode to view nearest bikes
    if len(current_operators_location) == 5:
        current_operators_location = current_operators_location[0:2]
        context = {
            'nearest_bikes_not_in_station': models.Bike.objects.filter(ifavailable=1, ifstation=0, postcode_len=5,postcode__startswith=current_operators_location),
            # nearest bikes  outside of a station,not rented and have the same location as the operator
            'other_bikes_not_in_station': models.Bike.objects.filter(ifavailable=1, ifstation=0).exclude(postcode_len=5,
                                                                                                         postcode__startswith=current_operators_location),
            # outher bikes outside of a station,not rented and have a different location as the operator
            'nearest_bikes_in_station': models.Bike.objects.filter(ifavailable=1, ifstation=1, postcode_len=5,
                                                                   postcode__startswith=current_operators_location),
            # nearest bikes that are in a station
            'other_bikes_in_station': models.Bike.objects.filter(ifavailable=1, ifstation=1).exclude(postcode_len=5,
                                                                                                     postcode__startswith=current_operators_location),
            # other bikes that are in a station
        }
    else:
        current_operators_location = current_operators_location[0:3]
        if len(current_operators_location) == 5:
            current_operators_location = current_operators_location[0:2]
        context = {
            'nearest_bikes_not_in_station': models.Bike.objects.filter(ifavailable=1, ifstation=0, postcode_len=6,
                                                                       postcode__startswith=current_operators_location),
            # nearest bikes  outside of a station,not rented and have the same location as the operator
            'other_bikes_not_in_station': models.Bike.objects.filter(ifavailable=1, ifstation=0).exclude(postcode_len=6,
                                                                                                         postcode__startswith=current_operators_location),
            # outher bikes outside of a station,not rented and have a different location as the operator
            'nearest_bikes_in_station': models.Bike.objects.filter(ifavailable=1, ifstation=1, postcode_len=6,
                                                                   postcode__startswith=current_operators_location),
            # nearest bikes that are in a station
            'other_bikes_in_station': models.Bike.objects.filter(ifavailable=1, ifstation=1).exclude(postcode_len=6,
                                                                                                     postcode__startswith=current_operators_location),
            # other bikes that are in a station
        }

    return render(request, 'viewbikes.html', context)

@operator_required
def operator_move_bike(request,id):
    current_id = id
    if request.method == "GET":
        
        station = models.Station.objects.all()
        return render(request, 'bike_form.html', {"station": station})
    else:
        station = request.POST.get('station')
        if station == "Select a station to move bike":
            station = models.Station.objects.all()
            return render(request, 'bike_form.html',  {"station": station})
        bike_obj = models.Bike.objects.filter(bikeid = id)
        station = models.Station.objects.filter(name = station)
        models.Bike.objects.filter(bikeid=bike_obj[0].bikeid).update(ifavailable=1,station=station[0],ifstation=1,postcode = station[0].postcode)
        
        return render(request, 'bikeinfo.html',{'current_bike': bike_obj} )




######################################################################################## Yiming ####################################################################################################################

@customer_required
def step1(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    if request.method == 'GET':
        return render(request, 'step1.html', locals())
    else:
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        userid = int(is_login[1:])
        rents = models.Rentdetails.objects.filter(userid=userid).all()

        if len(rents) != 0:
            rent = rents[len(rents) - 1]

            if rent.end_position == None:
                messages.error(request, 'You are already renting a bike. Please return it to rent again')
                return render(request, 'step1.html', locals())
        postcode = request.POST.get('postcode')
        postcode = postcode.replace(" ", "")
        if (postcode.startswith('G') or postcode.startswith('g')) and len(postcode) >= 5 and len(postcode) <= 6:

            if len(postcode) == 5:
                postcode = postcode[0:2]
                nearest_station = models.Station.objects.filter(postcode_len=5, postcode__startswith=postcode)
                if len(nearest_station) != 0:
                    nearest_station_id = nearest_station[0].stationid
                    other_stations = models.Station.objects.exclude(postcode_len=5, postcode__startswith=postcode)
                    nearest_bikes = len(models.Bike.objects.filter(station_id=nearest_station[0].stationid).all())
                    other_bikes = []
                    other_stations_id = []
                    for i in other_stations:
                        other_bikes.append(len(models.Bike.objects.filter(station_id=i.stationid).all()))
                        other_stations_id.append(i.stationid)

                    other = []
                    for i in range(0, len(other_stations)):
                        other.append(tuple((other_stations[i], other_bikes[i], other_stations_id[i])))

                    # print(other)

                    context = {
                        'nearest_station': nearest_station,
                        'nearest_station_id': nearest_station_id,
                        # 'other_stations': other_stations,
                        'nearest_bikes': nearest_bikes,
                        # 'other_bikes':other_bikes,
                        # 'other_stations_id': other_stations_id
                        'other': other
                    }
                else:
                    other_stations = models.Station.objects.all()
                    other_bikes = []
                    other_stations_id = []
                    for i in other_stations:
                        other_bikes.append(len(models.Bike.objects.filter(station_id=i.stationid).all()))
                        other_stations_id.append(i.stationid)

                    other = []
                    for i in range(0, len(other_stations)):
                        other.append(tuple((other_stations[i], other_bikes[i], other_stations_id[i])))
                    context = {
                        # 'other_bikes':other_bikes,
                        # 'other_stations_id': other_stations_id
                        'other': other
                    }

            if len(postcode) == 6:
                postcode = postcode[0:3]
                nearest_station = models.Station.objects.filter(postcode_len=6, postcode__startswith=postcode)
                if len(nearest_station) != 0:
                    nearest_station_id = nearest_station[0].stationid
                    other_stations = models.Station.objects.exclude(postcode_len=6, postcode__startswith=postcode)
                    nearest_bikes = len(models.Bike.objects.filter(station_id=nearest_station[0].stationid).all())
                    other_bikes = []
                    other_stations_id = []
                    for i in other_stations:
                        other_bikes.append(len(models.Bike.objects.filter(station_id=i.stationid).all()))
                        other_stations_id.append(i.stationid)
                    other = []
                    for i in range(0, len(other_stations)):
                        other.append(tuple((other_stations[i], other_bikes[i], other_stations_id[i])))

                    # print(other)
                    context = {
                        'nearest_station': nearest_station,
                        'nearest_station_id': nearest_station_id,
                        # 'other_stations': other_stations,
                        'nearest_bikes': nearest_bikes,
                        # 'other_bikes':other_bikes,
                        # 'other_stations_id': other_stations_id,
                        'other': other}
                else:
                    other_stations = models.Station.objects.all()
                    other_bikes = []
                    other_stations_id = []
                    for i in other_stations:
                        other_bikes.append(len(models.Bike.objects.filter(station_id=i.stationid).all()))
                        other_stations_id.append(i.stationid)

                    other = []
                    for i in range(0, len(other_stations)):
                        other.append(tuple((other_stations[i], other_bikes[i], other_stations_id[i])))
                    context = {

                        'other': other
                    }

            return render(request, 'step1.html', locals())
        else:
            messages.error(request, 'Insert glasgow postcode')
            return render(request, 'step1.html', locals())


@customer_required
def input(request, id):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    if request.method == "GET":
        bike = models.Bike.objects.filter(station_id=id)

        return render(request, 'input.html', {"id": id, "bike": bike, "user_obj": user_obj})
    else:
        station = request.POST.get('station')
        bike = request.POST.get('bike')
        if bike == "select a bike to rent":
            bike = models.Bike.objects.filter(station_id=id)
            return render(request, 'input.html', {"id": id, "bike": bike, "user_obj": user_obj})

        current_station = models.Station.objects.filter(stationid=id)
        # set new bike properties
        models.Bike.objects.filter(bikeid=bike).update(ifavailable=0, station=None, ifstation=0)

        # create new rentdetails
        rent = models.Rentdetails()
        rent.userid_id = userid
        rent.bikeid_id = bike
        rent.start_pick = date.today()
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        hour, minutes, seconds = current_time.split(':', 3)
        current_time = time(int(hour), int(minutes), int(seconds))
        rent.end_time = current_time
        rent.save()
        rent.start_postion = current_station[0].postcode

        rent.save()

        # return a confirmation message
        messages.success(request, 'Rent was successful')
        return render(request, 'customer_index.html', locals())


@customer_required
def return_car(request):
    if request.method == 'GET':
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        userid = int(is_login[1:])
        user_obj = models.User.objects.get(userid=userid)
        return render(request, 'rentinformation.html', locals())
    else:
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        userid = int(is_login[1:])
        user_obj = models.User.objects.get(userid=userid)
        station = request.POST.get('station')
        station = station.replace(" ","")
        rents = models.Rentdetails.objects.filter(userid=userid).all()
        if len(rents) == 0:
            messages.error(request,'You have no ongoing rents')
            return render(request, 'rentinformation.html',locals()) 

        rent = rents[len(rents)-1]
        #print(rent)
        if rent.end_position == None:
            #stations = models.Station.objects.filter(postcode=station).first()
            if len(station) == 5 or len(station)==6:
                if ((station.startswith('G') ) and station[1] in ['1','2','3','4','5','6','7','8','9'] and len(station)==5) or ((station.startswith('G')) and station[1:3] in ['10','11','12','13','14','15','16','17','18','19'] and len(station)==6):       
            
                    rent.end_position = station
                    rent.end_left = date.today()
                    now = datetime.now()
                    current_time = now.strftime("%H:%M:%S")
                    hour,minutes,seconds = current_time.split(':',3)
                    current_time = time(int(hour), int(minutes), int(seconds)) 
                    rent.end_time = current_time
                    rent.save()

                    bike = rent.bikeid
                    #set new bike properties
                    models.Bike.objects.filter(bikeid=bike.bikeid).update(ifavailable=1,station=None,ifstation=0,postcode = station)

                    start_date = rent.start_pick
                    end_date = rent.end_left
                    start_hour = rent.start_time
                    end_hour = rent.end_time
                    start = datetime.combine(start_date, start_hour)
                    end = datetime.combine(end_date, end_hour)
                    paytime = end - start 
                    paytime = paytime.total_seconds()/60
       
                    payamount = paytime*0.1
                    payamount = decimal.Decimal(payamount)
                    payamount = round(payamount,2)
            
                    user = models.User.objects.filter(userid=userid)
                    if payamount > user[0].amount: 
                        return redirect('/topup')
                    else:
                        return redirect('/pay')
                else:
                    messages.error(request,'Insert a glasgow postcode')
                    return render(request, 'rentinformation.html',locals())         
            else:
                messages.error(request,'Insert a glasgow postcode')
                return render(request, 'rentinformation.html',locals())   
        else:
            messages.error(request,'You have no ongoing rents')
            return render(request, 'rentinformation.html',locals()) 


################################################################################################### Konstantinos ########################################################################################################

# Report defective bike
@customer_required
def defective(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    if request.method == 'GET':
        return render(request, 'defective.html', locals())


    else:
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        userid = int(is_login[1:])
        rents = models.Rentdetails.objects.filter(userid=userid).all()
        if len(rents) == 0:
            messages.error(request, 'You have no ongoing rents')
            return render(request, 'defective.html', locals())
        rent = rents[len(rents) - 1]
        # print(rents)
        if rent.end_position != None:
            messages.error(request, 'You have no ongoing rents')
            return render(request, 'defective.html', locals())

        bike = rent.bikeid
        post = request.POST['postcode']
        post = post.replace(" ", "")

        bike_part = request.POST['part']
        details = request.POST['details']
        subject = "Bike needs repair"
        message = str(str(bike) + "\n" + bike_part + "\n" + details)

        if len(post)>6 or len(post)<5:
           
            post_err= "Insert glasgow postcode"
        
            return render(request, 'defective.html', locals())
        if ((post.startswith('G')) and post[1] in ['1', '2', '3', '4', '5', '6', '7', '8','9'] and len(post) == 5) or ((post.startswith('G') ) and post[1:3] in ['10', '11', '12', '13', '14', '15','16', '17', '18', '19'] and len(post) == 6):

            #availableOps = models.User.objects.filter(group=1, postcode__startswith=post[0:1].capitalize()).all()
            #if len(availableOps) != 0:
             #   i = np.random.choice(len(availableOps)-1)
              #  chosenOp = availableOps[i]
                # send email to available operator
               # send_mail(
                #    subject,
                 #   message,
                  #  'defectivebikesharing@gmail.com',
                   # [chosenOp.email]
                #)

            models.Bike.objects.filter(bikeid=bike.bikeid).update(ifavailable=1, ifdefective=1, ifstation=0,defective_details=message, postcode=post,station=None)
            rent.end_position = post
            rent.end_left = date.today()
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            hour, minutes, seconds = current_time.split(':', 3)
            current_time = time(int(hour), int(minutes), int(seconds))
            rent.end_time = current_time
            rent.save()

            start_date = rent.start_pick
            end_date = rent.end_left
            start_hour = rent.start_time
            end_hour = rent.end_time
            start = datetime.combine(start_date, start_hour)
            end = datetime.combine(end_date, end_hour)
            paytime = end - start
            paytime = paytime.total_seconds() / 60

            payamount = paytime * 0.1
            payamount = decimal.Decimal(payamount)
            payamount = round(payamount, 2)

            user = models.User.objects.filter(userid=userid)
            if payamount > user[0].amount:
                return redirect('/topup')
            else:
                amount = user[0].amount - payamount
                models.User.objects.filter(userid=userid).update(amount=amount)
                return redirect('/pay')
        else:
            
            post_err= "Insert glasgow postcode"
            
            return render(request, 'defective.html', locals())


# Customer Payment
@customer_required
# show amount in every customer's page
def customer_index(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    return render(request, 'customer_index.html', locals())


def pay(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    rents = models.Rentdetails.objects.filter(userid=userid).all()
    rent = rents[len(rents) - 1]
    start_date = rent.start_pick
    end_date = rent.end_left
    start_hour = rent.start_time
    end_hour = rent.end_time
    start = datetime.combine(start_date, start_hour)
    end = datetime.combine(end_date, end_hour)
    paytime = end - start
    paytime = paytime.total_seconds() / 60

    payamount = paytime * 0.1
    payamount = decimal.Decimal(payamount)
    payamount = round(payamount, 2)

    user = models.User.objects.filter(userid=userid)
    if payamount > user[0].amount:
        return redirect(topup)
    amount = user[0].amount - payamount
    models.User.objects.filter(userid=userid).update(amount=amount)

    return render(request, 'pay.html', {'payamount': payamount, 'user_obj': user_obj})


# Customer tops up his credit
@customer_required
def topup(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    userid = int(is_login[1:])
    user_obj = models.User.objects.get(userid=userid)
    if request.method == 'GET':
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        userid = int(is_login[1:])
        rents = models.Rentdetails.objects.filter(userid=userid).all()
        rent = rents[len(rents) - 1]
        start_date = rent.start_pick
        end_date = rent.end_left
        start_hour = rent.start_time
        end_hour = rent.end_time
        start = datetime.combine(start_date, start_hour)
        end = datetime.combine(end_date, end_hour)
        paytime = end - start
        paytime = paytime.total_seconds() / 60

        payamount = paytime * 0.1
        payamount = decimal.Decimal(payamount)
        payamount = round(payamount, 2)
        user = models.User.objects.filter(userid=userid)
        current_amount = user[0].amount
        context = {
            'payamount': payamount,
            'current_amount': current_amount
        }

        return render(request, 'topup.html', locals())


    else:
        is_login = request.get_signed_cookie('is_login', salt='s7', default='')
        userid = int(is_login[1:])
        user = models.User.objects.filter(userid=userid)

        topup = request.POST['amount']
        current_amount = user[0].amount
        total = current_amount + decimal.Decimal(topup)
        models.User.objects.filter(userid=userid).update(amount=total)
        rents = models.Rentdetails.objects.filter(userid=userid).all()
        rent = rents[len(rents) - 1]
        start_date = rent.start_pick
        end_date = rent.end_left
        start_hour = rent.start_time
        end_hour = rent.end_time
        start = datetime.combine(start_date, start_hour)
        end = datetime.combine(end_date, end_hour)
        paytime = end - start
        paytime = paytime.total_seconds() / 60
        payamount = paytime * 0.1
        payamount = round(payamount, 2)

        return redirect('/pay')


################################################################################### Arwa and Umroh ##############################################################################################

@manager_required
def bike_activites(request):
   is_login = request.get_signed_cookie('is_login', salt='s7', default='')
   manager = int(is_login[1:])
   managerid = models.User.objects.filter(userid=manager)
   managerid = managerid[0]
   if path.exists('media/images/bikeA.png'):
       os.remove('media/images/bikeA.png')
   if path.exists('media/images/user.png'):
        os.remove('media/images/user.png')
   if path.exists('media/images/peaktime.png'):
        os.remove('media/images/peaktime.png')
   if path.exists('media/images/peaktimeE.png'):
        os.remove('media/images/peaktimeE.png')
   if path.exists('media/images/loEnd.png'):
        os.remove('media/images/loEnd.png')
   if path.exists('media/images/loPicked.png'):
        os.remove('media/images/loPicked.png')
    
   data=models.Rentdetails.objects.values('bikeid').annotate(dcount=Count('bikeid'))
   data1 = []
   for i in data:
       data1.append(i)
   #print(data[0])
   bikes = models.Bike.objects.all()
   x = []
   y = []
   for i in data:
       x.append(str(i['bikeid']))
       y.append(int(i['dcount']))
   for i in bikes:
       is_found = False
       for j in x:
           if str(i.bikeid) == j:
              # print(str(i.bikeid),j)
               is_found = True
       if (is_found == False):
            x.append(str(i.bikeid))
            y.append(0)
            data1.append({'bikeid': i.bikeid, 'dcount': 0})
   #print(y)
 
   #pd=read_frame(data)
   #x=pd['bikeid']
   plt.xticks(np.arange(len(x)),x)
   plt.yticks(y)
   #y=pd['dcount']
   plt.bar(x,y,align='center')

   plt.xlabel('Bike ID')
   plt.ylabel('Times the bike has been rented')
   plt.title('Rent Activities For Each Bike')
   img=plt.savefig('media/images/bikeA.png')
   plt.close()
   Reoprt1=models.Report(managerid=managerid,imgaeReport='media/images/bikeA.png')
   Reoprt1.save()
   #ImageR=Report.imgaeReport.get()



   return render(request,'bikeactivties.html',{'data':data1})

@manager_required
def User_activites(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    manager = int(is_login[1:])
    managerid = models.User.objects.filter(userid=manager)
    managerid = managerid[0]
    if path.exists('media/images/bikeA.png'):
      os.remove('media/images/bikeA.png')
    if path.exists('media/images/user.png'):
        os.remove('media/images/user.png')
    if path.exists('media/images/peaktime.png'):
        os.remove('media/images/peaktime.png')
    if path.exists('media/images/peaktimeE.png'):
        os.remove('media/images/peaktimeE.png')
    if path.exists('media/images/loEnd.png'):
        os.remove('media/images/loEnd.png')
    if path.exists('media/images/loPicked.png'):
        os.remove('media/images/loPicked.png')
    datauser= models.Rentdetails.objects.values('userid').annotate(dcount=Count('userid'))
    data1 = []
    for i in datauser:
        data1.append(i)
    users = models.User.objects.filter(group=0)
    #print(users)
    x = []
    y = []
    for i in datauser:
       x.append(str(i['userid']))
       y.append(int(i['dcount']))
    
    for i in users:
       is_found = False
       for j in x:
           if str(i.userid) == j:
              # print(str(i.bikeid),j)
               is_found = True
       if (is_found == False):
            x.append(str(i.userid))
            y.append(0)
            data1.append({'userid': i.userid, 'dcount': 0})

    plt.yticks(np.arange(len(x)),x)

    
    #pd = read_frame(datauser)
    #x = pd['userid']
    #y = pd['dcount']
    plt.barh(x, y, align='center')

    plt.xlabel('Number of times the user has rented from App')
    plt.ylabel('User ID')
    plt.title('User Rent Activties')
    img2=plt.savefig('media/images/user.png')
    plt.close()
    Reoprt1 = models.Report(managerid=managerid, imgaeReport='/media/images/user.png')
    Reoprt1.save()
    return render(request,'useractivtes.html',{'datauser':data1})

@manager_required
def Peak_time(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    manager = int(is_login[1:])
    managerid = models.User.objects.filter(userid=manager)
    managerid = managerid[0]
    if path.exists('media/images/bikeA.png'):
          os.remove('media/images/bikeA.png')
    if path.exists('media/images/user.png'):
        os.remove('media/images/user.png')
    if path.exists('media/images/peaktime.png'):
        os.remove('media/images/peaktime.png')
    if path.exists('media/images/peaktimeE.png'):
        os.remove('media/images/peaktimeE.png')
    if path.exists('media/images/loEnd.png'):
        os.remove('media/images/loEnd.png')
    if path.exists('media/images/loPicked.png'):
        os.remove('media/images/loPicked.png')
    peakTimeS=models.Rentdetails.objects.values('start_time').annotate(dcount=Count('start_time'))
    peakTimeE=models.Rentdetails.objects.values('end_time').annotate(dcount=Count('end_time'))

    times = ['12AM','1AM','2AM','3AM','4AM','5AM','6AM','7AM','8AM','9AM','10AM','11AM','12PM','13PM','14PM','15PM','16PM','17PM','18PM','19PM','20PM','21PM','22PM','23PM']
    number_of_rents = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    for i in peakTimeS:
        time = str(i['start_time'])
        #print(time)
        if time[0] == '0':
            #print(time)
            time = int(time[1])
            if time == 0:
                number_of_rents[0] = number_of_rents[0] + 1
            else:
                number_of_rents[time] =  number_of_rents[time] + 1
        else:
            time = int(time[0:2])   
            number_of_rents[time] =  number_of_rents[time] + 1
    #print(peakTimeS)
    #print(number_of_rents)

    
    plt.plot(times,number_of_rents)
    plt.xlabel("Rents' starting time")
    plt.ylabel('Number of rents that started at that time')
    plt.title('Peak Time Of Renting A Bike')
    plt.xticks(rotation = 20)
    img3 = plt.savefig('media/images/peaktime.png')
    plt.close()
    Reoprt1 = models.Report(managerid=managerid, imgaeReport='media/images/peaktime.png')
    Reoprt1.save()

    number_of_returns = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    for i in peakTimeE:
        time = str(i['end_time'])
        #print(time)
        if time[0] == '0':
            #print(time)
            time = int(time[1])
            if time == 0:
                number_of_returns[0] = number_of_returns[0] + 1
            else:
                number_of_returns[time] =  number_of_returns[time] + 1
        else:
            time = int(time[0:2])   
            number_of_returns[time] =  number_of_returns[time] + 1
    #print(peakTimeS)
    #print(number_of_returns)
    plt.plot(times,number_of_returns)
    plt.xlabel("Rent's ending time")
    plt.ylabel('Number of rents that ended at that time')
    plt.title('Peak Time Of Returning A Bike')
    plt.xticks(rotation = 20)
    img4 = plt.savefig('media/images/peaktimeE.png')
    plt.close()
    Reoprt1 = models.Report(managerid=managerid, imgaeReport='media/images/peaktimeE.png')
    Reoprt1.save()
   


    return render(request,'peaktime.html',{})

@manager_required
def locations(request):
    is_login = request.get_signed_cookie('is_login', salt='s7', default='')
    manager = int(is_login[1:])
    managerid = models.User.objects.filter(userid=manager)
    managerid = managerid[0]
    if path.exists('media/images/bikeA.png'):
        os.remove('media/images/bikeA.png')
    if path.exists('media/images/user.png'):
        os.remove('media/images/user.png')
    if path.exists('media/images/peaktime.png'):
        os.remove('media/images/peaktime.png')
    if path.exists('media/images/peaktimeE.png'):
        os.remove('media/images/peaktimeE.png')
    if path.exists('media/images/loEnd.png'):
        os.remove('media/images/loEnd.png')
    if path.exists('media/images/loPicked.png'):
        os.remove('media/images/loPicked.png')
    loc=models.Rentdetails.objects.values('start_postion').annotate(dcount=Count('start_postion'))
    pd=read_frame(loc)
    x=pd['start_postion']
    y=pd['dcount']
    plt.title('Most Picked Stations As Starting Point')
    plt.pie(y,labels=x,shadow=True,autopct='%1.1f%%',startangle=180)
    plt.axis('equal')
    img5=plt.savefig('media/images/loPicked.png')
    plt.close()
    Reoprt1 = models.Report(managerid=managerid, imgaeReport=img5)
    Reoprt1.save()

    loc2= models.Rentdetails.objects.values('end_position').annotate(dcount=Count('end_position'))
    pd2=read_frame(loc2)
    x2=pd2['end_position']
    y2=pd2['dcount']
    plt.title('Most Picked Postcodes As Ending Point')
    plt.pie(y2, labels=x2, shadow=True, autopct='%1.1f%%',startangle=180)
    plt.axis('equal')
    img6 = plt.savefig('media/images/loEnd.png')
    plt.close()
    Reoprt1 = models.Report(managerid=managerid, imgaeReport=img6)
    Reoprt1.save()

    return render(request,'locationsMost.html',{})

    #############################################################################################################################################################################################