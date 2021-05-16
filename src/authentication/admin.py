from django.contrib import admin

from .models import Users

class UsersAdmin(admin.ModelAdmin):
    pass
admin.site.register(Users,UsersAdmin)
