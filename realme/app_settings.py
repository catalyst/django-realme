from os.path import join
from django.conf import settings

# override `bundels.BUNDLES_DEFAULT` in settings.py
BUNDLES = getattr(settings, 'BUNDLES', {})

# abs path to bundles directory, defaults to `bundles` in repo root
BUNDLES_ROOT = getattr(settings, 'BUNDLES_ROOT', join(settings.BASE_DIR, 'bundles'))

# One of the keys in Bundles, or FAKE
BUNDLE_NAME = getattr(settings, 'BUNDLE_NAME', 'FAKE')

# store realme error in this cookie for frontend to use
EXCHANGE_COOKIE_NAME = getattr(settings, 'EXCHANGE_COOKIE_NAME', 'realme_auth')

# Organization info used to render metadata.xml
METADATA_ORG_NAME = getattr(settings, 'METADATA_ORG_NAME', 'Catalyst')
METADATA_ORG_DISPLAY_NAME = getattr(settings, 'METADATA_ORG_DISPLAY_NAME', 'Catalyst IT')
METADATA_ORG_URL = getattr(settings, 'METADATA_ORG_URL', 'https://www.catalyst.net.nz')
