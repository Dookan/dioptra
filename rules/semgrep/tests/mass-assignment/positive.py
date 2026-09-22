def create(request):
    # ruleid: python-django-mass-assignment
    user = User(**request.POST)
    # ruleid: python-django-mass-assignment
    Profile.objects.create(**request.data)
    return user
