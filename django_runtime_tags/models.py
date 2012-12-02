""" The RuntimeTag model allows users to create and edit key/value
    pairs via the Django admin.  The keys can be anything that would
    be valid in a Django template.  The values can be anything that can
    be pickled, pretty much.  That includes Booleans, strings, lists,
    dictionaries, integers and floats, and complex combinations thereof.
    Note that this uses a safe version of eval, but it's probably a good
    idea to only make available to trusted personnel.  
"""
import types
import logging
from datetime import datetime
from django.db import models
from django import template
from django_runtime_tags.pickled_object_field import PickledObjectField

log = logging.getLogger()

register = template.Library()

class RuntimeTag(models.Model):
    key = models.CharField(max_length=50,
            db_index=True,
            unique=True,
            help_text='Use {{ Key }} in the template',
            )
    value = PickledObjectField(editable=True,
            convert=True,
            help_text='Use True, False, arbitrary Text, or any serializable Python value!'
            )
    valid_start = models.DateTimeField(default=datetime.now(),
            help_text='Make template variable available starting at this date/time',
            )


    def __unicode__(self):
        return "%s = %s" % (self.key, self.value)

