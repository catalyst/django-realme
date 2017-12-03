from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from ...bundles import Bundle


class Command(BaseCommand):
    help = "Render metadata.xml"

    def add_arguments(self, parser):
        parser.add_argument('--site-url')
        parser.add_argument('--bundles-root')
        parser.add_argument('--bundle-name')

    def handle(self, *args, **options):
        b = Bundle(
            site_url=options.get('site_url'),
            bundles_root=options.get('bundles_root'),
            name=options.get('bundle_name'),
        )
        self.stdout.write(b.render_metadata())

