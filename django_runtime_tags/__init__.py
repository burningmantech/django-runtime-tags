from datetime import datetime
from django.utils import timezone

def runtime_value(tag):
    from models import RuntimeTag
    """ Returns the value of the tag, or None if the tag doesn't exist."""
    try:
        rtt = RuntimeTag.objects.get(key=tag, valid_start__lt=timezone.now())
        return rtt.value
    except RuntimeTag.DoesNotExist:
        return None

def runtime_tags():
    from models import RuntimeTag
    return RuntimeTag.objects.filter(valid_start__lt=timezone.now()).order_by('key')
