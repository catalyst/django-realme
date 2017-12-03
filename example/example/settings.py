"""
Django settings for example project.

Generated by 'django-admin startproject' using Django 1.11.6.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.11/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 't8g9=0z5_r5y#cvv00dg^i2o8^ui@gp@z3nvj@dtw68$m4h0px'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'realme',  # --> install realme app
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'realme.backends.SamlBackend',
)

LOGOUT_REDIRECT_URL = '/'

ROOT_URLCONF = 'example.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates')
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'example.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/'


SITE_NAME = 'example'
SITE_DOMAIN = 'localhost:8000'
SITE_URL = 'http://localhost:8000'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '%(asctime)s %(levelname)-8s %(pathname)s#%(lineno)d: \n%(message)s\n'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        }
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARN',
        },
        'realme': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}

BUNDLE_NAME = 'MTS'

BUNDLES_ROOT = os.path.join(BASE_DIR, 'bundles')

BUNDLES = {
    'MTS': {
        'sp_entity_id': 'https://example.com/sp/example',
        'site_url': 'http://localhost:8000',
    },
    'ITE-uat': {
        'sp_entity_id': 'https://example.com/sp/example',
        'site_url': 'https://uat.example.com',
        'saml_sp_cer': 'ite.sa.saml.sig.uat.example.com.crt',
        'saml_sp_key': 'ite.sa.saml.sig.uat.example.com.private.key',
    },
    'ITE-testing': {
        'sp_entity_id': 'https://example.com/sp/test01',
        'site_url': 'https://test01.example.com',
        'saml_sp_cer': 'ite.sa.saml.sig.test01.example.com.crt',
        'saml_sp_key': 'ite.sa.saml.sig.test01.example.com.private.key',
    },
    'PRD': {
        'sp_entity_id': 'https://example.com/sp/example',
        'site_url': 'https://example.com',
        'saml_sp_cer': 'prod.sa.saml.sig.example.com.crt',
        'saml_sp_key': 'prod.sa.saml.sig.example.com.private.key',
    }
}
