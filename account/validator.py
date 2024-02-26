import re
from django.core.exceptions import ValidationError



def no_special_charecters(value):
    # if re.search(r'[!@#$%^&*(),.?":{}|<>-~/\;=+ ]', value):
    if re.search(r'[^a-zA-Z0-9_]', value):
        raise ValidationError("Special characters and spaces are not allowed...You can use underscore (_) and numbers(0-9)")
    else:
        pass