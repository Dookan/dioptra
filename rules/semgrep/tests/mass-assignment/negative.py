def create(request):
    form = UserForm(request.POST)
    if form.is_valid():
        # ok: python-django-mass-assignment
        user = User(name=form.cleaned_data["name"])
        return user
    return None
