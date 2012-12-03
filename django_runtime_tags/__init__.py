from datetime import datetime
from models import RuntimeTag

def runtime_value(tag):
    """ Returns the value of the tag, or None if the tag doesn't exist."""
    try:
        rtt = RuntimeTag.objects.get(key=tag, valid_start__lt=datetime.now())
        return rtt.value
    except RuntimeTag.DoesNotExist:
        return None

def runtime_tags():
    return RuntimeTag.objects.filter(valid_start__lt=datetime.now()).order_by('key')
