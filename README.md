# django-realme: a Django app for integrating the RealMe authentication service

This is a Django package and a small example Django application to show how to
use the RealMe authentication service with your Django project. All instructions
are based on Ubuntu 16.04 LTS.


## Install prerequisites

- libxmlsec1-dev
- pkg-config


## Stages and Environments

The RealMe authentication service is divided into three separate environments,
split up by function: development, testing, and production. These are:

- Stage 1: Message Test Site (MTS)
- Stage 2: Integration Test Environment (ITE)
- Stage 3: Production Environment (PRD)


## Bundles

For each environment above, RealMe will provide a Bundle zip file:

- Integration Bundle MTS V2.1.zip
- Integration Bundle ITE V2.0.zip
- Integration Bundle Production V2.0.zip

Each Bundle contains the keys, certificates and configuration for integrating
with the RealMe service. For MTS, it contains a pre-built sample key and
certificate, so you can use them directly for development. For ITE and PRD, you
have to create your own key and certificate.

In this app, we require you to put all the bundles into a directory, and put
your key and certificate into each bundle. You may need to split them into
mulitiple environments. For example, in endoflife, we split ITE into `ITE-uat`
and `ITE-testing`, each with its own key and certificate files. The directory
layout is as follows:
```
    bundles
    ├── MTS
    ├── ITE-uat
    ├── ITE-testing
    └── PRD
```


## Create key and cert for ITE and PRD

To generate certificates for ITE and PRD, you will need to go through a
checklist with the Department of Internal affairs. Part of this is using OpenSSL
to generate a private key and CSR:

    STAGE=ite  # or prod
    DOMAIN=$STAGE.sa.saml.sig.mysite.mydomain.nz;
    PK_FILE="$DOMAIN.private.key"
    CSR_FILE="$DOMAIN.csr"
    GPG_FILE="$PK_FILE.gpg"
    openssl req -new -nodes -newkey rsa:2048 -keyout $PK_FILE -out $CSR_FILE \
        -subj "/C=NZ/O=Department of Internal Affairs/OU=Births, Deaths and Marriages/CN=$DOMAIN";

Then send the CSR to DIA for approval, and they will hopefully furnish you with
a certificate.

More documentation about this process and the specification may be available
here: https://see.govt.nz/realme/realme/Library/Forms/Library.aspx


## Django settings

- Add `realme` and `django.contrib.sessions` to `INSTALLED_APPS`
- Add `realme.backends.SamlBackend` to `AUTHENTICATION_BACKENDS`
- Make sure `django.contrib.sessions.middleware.SessionMiddleware` is in `MIDDLEWARE`
- Set `BUNDLES_ROOT` to your bundles directory
- Set `BUNDLE_NAME` to one of `FAKE`, `MTS`, `ITE`, `PRD` as appropriate
- Adjust `BUNDLES` with settings to override realme.bundles.BUNDLES_DEFAULT

Refer to the supplied `example/example/settings.py` for examples.

The `site_url` in `BUNDLES` is optional, you can also set it with a global
`SITE_URL` setting.

While loading the bundle configuration, the code will load
`realme.bundles.BUNDLES_DEFAULT` first, and merge settings from `settings.BUNDLES`.


## URLs

Set up the URLs as follows:
```
    from django.conf.urls import url, include
    urlpatterns = [
        ...
        url(r'^realme/', include('realme.urls', namespace='realme')),
        ...
    ]
```

Then you can use the RealMe URLs in templates:

```
    {% url 'realme:login' %}
    {% url 'realme:logout' %}
    {% url 'realme:acs' %}
    ...
```

For login, it defaults to low strength, but you can specify with:

```
    {% url 'realme:login' %}?strength=low
    {% url 'realme:login' %}?strength=moderate
```


## Metadata

We provide two ways to generate metadata:

1. login to the site as admin and save the `/realme/metadata` URL as an XML file.
2. run the `render_metadata` Django management command.

For the MTS RealMe service, you can upload an XML file containing this metadata
to the MTS site:

1. Navigate to https://mts.realme.govt.nz/logon-mts/metadataupdate
2. Select your XML file and click the "Upload" button.
3. In the next screen, click the "Import" button.

For ITE and PRD, you need access to https://see.govt.nz/realme/realme to
upload the metadata. Once that is done you can notify the DIA team, and wait for
them to apply it.


## Seamless logon

This app has code for seamless logon but at this stage it is not fully verified.
