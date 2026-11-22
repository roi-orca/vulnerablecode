#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from django.http import HttpResponse
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.throttling import SimpleRateThrottle


class SearchViewRateThrottle(SimpleRateThrottle):
    """
    Throttle expensive web UI searches by client IP address.
    """

    scope = "web_search"
    rate = "30/minute"

    def get_cache_key(self, request, view):
        user = getattr(request, "user", None)
        if user is not None and (user.is_superuser or user.is_staff):
            return None
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class SearchViewThrottleMixin:
    """
    Apply ``SearchViewRateThrottle`` to Django (non-DRF) views when a search is requested.
    """

    def dispatch(self, request, *args, **kwargs):
        if request.GET.get("search"):
            throttle = SearchViewRateThrottle()
            if not throttle.allow_request(request, self):
                response = HttpResponse("Too many requests. Please try again later.", status=429)
                wait = throttle.wait()
                if wait:
                    response["Retry-After"] = str(int(wait))
                return response
        return super().dispatch(request, *args, **kwargs)


class StaffUserRateThrottle(ScopedRateThrottle):
    def allow_request(self, request, view):
        """
        Do not apply throttling for superusers and admins.
        """
        if request.user.is_superuser or request.user.is_staff:
            return True

        return super().allow_request(request, view)
