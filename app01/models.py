from django.db import models
from django.urls import reverse

# Some changes made by Xu Wang 8/2/2021:
# 1. Modify all the postcode fields max length as 6, which means it will not include any space.
# 2. Modify the 'postcode' field type of 'User class. Use the postcode itself instead of the foreign key of 'Station' class.
# 3. Add 'null=True' to the 'defective_details' field of 'Bike'class.
# 4. Add 'email' field to 'User' class to retrieve password.
# 5. Add 'Repwd_Request' class to retrieve password.

# Create your models here.
class User(models.Model):
    userid = models.AutoField(primary_key=True, editable=False)
    username = models.CharField(max_length=32, unique=True)  # varchar(32)
    password = models.CharField(max_length=78)  # varchar(32)
    postcode = models.CharField(max_length=6, blank=True, null=True)  # not include a space
    amount = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    group = models.IntegerField(default=0)  # costomer = 0, operator = 1, manager = 2
    email = models.EmailField(unique=True)


class Bike(models.Model):
    bikeid = models.AutoField(primary_key=True, editable=False)
    ifdefective = models.BooleanField(default=0)  # is_defective = 1
    ifavailable = models.BooleanField(default=1)  # is_avaliable = 1
    postcode = models.CharField(max_length=6)
    defective_details = models.CharField(max_length=30, blank=True, null=True)
    station = models.ForeignKey(to='Station', on_delete=models.SET_NULL, blank=True, null=True)  # stationid
    ifstation = models.BooleanField()  # if bike is in a station then ifstation = 1
    postcode_len = models.PositiveIntegerField(default=0)

    def save(self, *args, **kwargs):
        self.postcode_len = len(self.postcode)
        return super(Bike, self).save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('movebike-details', kwargs = {'pk':self.pk})

class Report(models.Model):
    reportid = models.AutoField(primary_key=True, editable=False)
    time = models.DateTimeField(auto_now_add=True)  # YYYY-MM-DD HH:MM:SS
    managerid = models.ForeignKey(to='User', on_delete=models.SET_NULL, null=True)
    imgaeReport=models.ImageField(upload_to='media/images', default=None)


class Station(models.Model):
    stationid = models.AutoField(primary_key=True, editable=False)
    postcode = models.CharField(max_length=6, default='G128QQ')  # not include a space
    name = models.CharField(max_length=32)
    postcode_len = models.PositiveIntegerField(default=0)

    def save(self, *args, **kwargs):
        self.postcode_len = len(self.postcode)
        return super(Station, self).save(*args, **kwargs)


class Repwd_Request(models.Model):
    requestid = models.AutoField(primary_key=True, editable=False)
    email = models.EmailField()
    requesttime = models.DateTimeField(auto_now_add=True)
    ifdeal = models.BooleanField(default=False)

class Rentdetails(models.Model):
    rentid = models.AutoField(primary_key=True, editable=False)
    userid = models.ForeignKey(to='User', on_delete=models.DO_NOTHING)
    bikeid = models.ForeignKey(to='Bike', on_delete=models.CASCADE, null= True)
    start_pick = models.DateField(auto_now_add=True)  # YYYY-MM-DD HH:MM:SS
    end_left = models.DateField(auto_now_add=True,null=True,blank=True)  # YYYY-MM-DD HH:MM:SS
    start_time=models.TimeField(auto_now_add=True)
    end_time=models.TimeField(auto_now_add=True,null=True,blank=True)
    start_postion = models.CharField(max_length=6)  # postcode
    end_position = models.CharField(max_length=6,null=True,blank=True)  # postcode