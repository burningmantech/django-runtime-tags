from django.contrib import admin
from django_runtime_tags.models import RuntimeTag


class RuntimeTagAdmin(admin.ModelAdmin):
    ordering = ['key']

    class Media:
        css = { 'all':('django_runtime_tags/css/rtt.css',) }

admin.site.register(RuntimeTag, RuntimeTagAdmin)
