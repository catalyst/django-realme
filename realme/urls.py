from django.conf.urls import url
from django.conf import settings
from django.contrib.auth.views import LogoutView

from . import views

urlpatterns = [
    url(r'^metadata/$', views.metadata, name='metadata'),
    url(r'^login/$', views.login, name='login'),
    url(r'^logout/$', LogoutView.as_view(), name='logout'),
    url(r'^acs/$', views.assertion_consumer_service, name='acs'),
    url(r'^seamless/(?P<target_sp>\w+)/$', views.seamless, name='seamless'),
]
