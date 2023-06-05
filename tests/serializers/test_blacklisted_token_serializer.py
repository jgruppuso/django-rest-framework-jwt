# -*- coding: utf-8 -*-

from datetime import datetime
from datetime import timedelta
from django.conf import settings
from django.utils import timezone

import pytest

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.blacklist.serializers import BlacklistTokenSerializer
from rest_framework_jwt.settings import api_settings


@pytest.mark.parametrize("id_setting", ["require", "include"])
def test_token_expiration_is_saved_as_utc(user, monkeypatch, id_setting):
    # temporarily change time zone
    monkeypatch.setattr(settings, "TIME_ZONE", "Asia/Tokyo")
    monkeypatch.setattr(api_settings, "JWT_TOKEN_ID", id_setting)
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    # pass token through serializer to test expires_at validity
    serializer = BlacklistTokenSerializer(data={"token": token})
    serializer.is_valid()
    bltoken = serializer.save()

    # token expiry datetime should be UTC
    assert bltoken.expires_at.tzinfo == timezone.utc
    # token expiry datetime handling should all be UTC (iat, expires_at) even though local timezone is different
    assert bltoken.expires_at == timezone.make_aware(
        datetime.utcfromtimestamp(payload.get("iat"))
        + timedelta(seconds=api_settings.JWT_EXPIRATION_DELTA.seconds),
        timezone=timezone.utc,
    )
