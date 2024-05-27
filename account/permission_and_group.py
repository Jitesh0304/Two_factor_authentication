from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from .models import *



user_one = User.objects.get(email='admin@gmail.com')


        ## add permissions to user
first_permission= Permission.objects.get(codename='add_group')
user_one.user_permissions.add(first_permission)
user_one.save()


        ## add user in a group
new_group, created_group = Group.objects.get_or_create(name = "SpecialGroup")
user_one.groups.add(new_group)
user_one.save()


        ## get all content for a model
all_contents = ContentType.objects.get_for_model(User)


        ## create permission and add that created permission to group
new_permission = Permission.objects.create(codename ='can_go_haridwar', name ='Can go to Haridwar',
                                           content_type = all_contents)
new_group.permissions.add(new_permission)
new_group.save()

