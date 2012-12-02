About
=====

This module permits runtime setting of tags via Django admin.

If you need additional support, please contact http://www.burningman.com/

Overview
========

Setup
-----

The easiest way to get started with the module is to install it from the
Python Package Index.

::

    pip install django-runtime-tags

You may need github access credentials.  Obtain them from Burning Man tech.

Add the context processor to the settings.py file:

::

    TEMPLATE_CONTEXT_PROCESSORS = (
        ...,
        'django_runtime_tags.context_processors.add_tags',
        )

Add the RuntimeTag model to the database with 

::

    python manage.py syncdb

Optionally, you can add a test template to urls.py, for example

::

    from django.views.generic.simple import direct_to_template
    if settings.DEBUG:
        urlpatterns += \
            patterns('',
                  url(r'^rtt/$', direct_to_template,
                      { 'template':"django_runtime_tags/tests.html" }),
            )

Then, just go the Django admin, and set some Tags to use in your templates.

Testing
-------

If you added the test link to your urls.py file, you can test your installation
like this.

::

    python manage loaddate django_runtime_tags/test_data

    python manage.py runserver 0.0.0.0:8000

    http://localhost:8000/rtt/


Dependencies
------------

Minimum Django version 1.3

Basic Design
------------

Template Tags can be set at runtime via the Django admin facility.
Tags are quite flexible and can contain Boolean, String and other 
Python types.  They are immediately available -- or, you can set a 
date & time in the future when they become valid.

Security
--------

This is intended to be accessed via the Django admin, and expected to be used
by staff with admin privileges.  Part of its flexibility comes from being able
to eval(uate) tag values as Python code.  A safe(er) version of eval is used,
but it *has not been tested to withstand deliberate exploits*.
