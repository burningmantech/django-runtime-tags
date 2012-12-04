from django.contrib import admin
from models import RuntimeTag

class RuntimeTagAdmin(admin.ModelAdmin):
    ordering = ['key']
    search_fields = ['key']

    class Media:
        css = { 'all':('django_runtime_tags/css/rtt.css',) }

admin.site.register(RuntimeTag, RuntimeTagAdmin)
