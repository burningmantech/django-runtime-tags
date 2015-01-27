"""
Add runtime variables to all pages
"""
from logging import getLogger
from pprint import PrettyPrinter
from models import RuntimeTag
from django.utils.timezone import now

log = getLogger('django-runtime-tags')

def add_tags(request):
    """Add template tags defined via Django admin to request context."""

    rt_tags = RuntimeTag.objects.filter(valid_start__lt=now())
    ctx = dict([(t.key, t.value) for t in rt_tags])
    ctx.update({'RUNTIME_TAGS':rt_tags})

    log.debug("Adding Runtime Tags: %s", PrettyPrinter(indent=4).pformat(ctx))

    return ctx

