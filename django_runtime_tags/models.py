""" The RuntimeTag model allows users to create and edit key/value
    pairs via the Django admin.  The keys can be anything that would
    be valid in a Django template.  The values can be anything that can
    be pickled, pretty much.  That includes Booleans, strings, lists,
    dictionaries, integers and floats, and complex combinations thereof.
    Note that this uses a safe version of eval, but it's probably a good
    idea to only make available to trusted personnel.  
"""
import types
from logging import getLogger

from django import template
from django.db import models
from django.core.validators import RegexValidator
from django.utils import timezone
from django_runtime_tags.pickled_object_field import PickledObjectField

log = getLogger('django-runtime-tags')

tagname_regex = r'^[\dA-Za-z]+[\dA-Za-z_.]*$'
value_regex = r'(?!.*__)'

class RuntimeTag(models.Model):
    key = models.CharField(
        db_index=True,
        max_length=50,
        unique=True,
        help_text='Use {{ Key }} in the template',
        validators=[RegexValidator(tagname_regex, 'Not a valid tag name')]
        )
    value = PickledObjectField(
        editable=True,
        convert=True,
        help_text='Use True, False, arbitrary Text, or any serializable Python value!',
        #couldn't get this to work...
        #validators=[RegexValidator(tagname_regex, u'Not a valid tag name')]
        )
    valid_start = models.DateTimeField(
        default=timezone.now,
        help_text='Make template variable available starting at this date/time',
        )
    description = models.TextField(
        null=True,
        blank=True,
        )

    class Meta:
        verbose_name = 'Runtime Tag'

    def __str__(self):
        return "%s = %s" % (self.key, self.value)

