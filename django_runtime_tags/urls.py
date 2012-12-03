from django.conf.urls.defaults import url, patterns
from django.views.generic.simple import direct_to_template

rtt_test_urlpatterns = patterns('',
    url(r'^rtt/test/$', direct_to_template, { 'template':"django_runtime_tags/tests.html" }),
)

