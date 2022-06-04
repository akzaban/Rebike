from django.contrib import admin
from .models import Bike,User,Station,Report,Rentdetails

# Register your models here.
admin.site.register(User)
admin.site.register(Bike)
admin.site.register(Station)
admin.site.register(Report)
admin.site.register(Rentdetails)
