from django.conf.urls import url, patterns
from django.views.generic.base import TemplateView

rtt_test_urlpatterns = patterns('',
    url(r'^rtt/test/$', TemplateView.as_view(template_name="django_runtime_tags/tests.html")),
)

