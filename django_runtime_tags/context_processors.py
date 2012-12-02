"""
Add common variables to all pages
"""
from logging import getLogger
from pprint import PrettyPrinter
from datetime import datetime
from django_runtime_tags.models import RuntimeTag

log = getLogger()

def add_tags(request):
    """Add template tags defined via Django admin to request context."""

    rt_tags = RuntimeTag.objects.filter(valid_start__lt=datetime.now())
    ctx = [(t.key, t.value) for t in rt_tags]

    log.debug("Adding Runtime Tags: %s", PrettyPrinter(indent=4).pformat(ctx))

    return ctx

