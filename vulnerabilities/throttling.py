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


class StaffUserRateThrottle(ScopedRateThrottle):
    def allow_request(self, request, view):
        """
        Do not apply throttling for superusers and admins.
        """
        if request.user.is_superuser or request.user.is_staff:
            return True

        return super().allow_request(request, view)


class ThrottledSearchMixin:
    """
    Enforce request-rate throttling on plain Django class-based views.

    DRF's ``DEFAULT_THROTTLE_CLASSES`` setting is only honored by DRF
    ``APIView``/``ViewSet`` subclasses: it is silently ignored by regular
    Django views such as ``ListView``. This mixin reuses the same
    ``StaffUserRateThrottle``/``ScopedRateThrottle`` machinery (and the
    shared ``DEFAULT_THROTTLE_RATES``) so expensive, unauthenticated search
    views cannot be hammered for free.

    Views using this mixin must set a ``throttle_scope`` attribute with a
    matching entry in ``REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]``.
    """

    throttle_classes = (StaffUserRateThrottle,)
    throttle_scope = None

    def get_throttles(self):
        return [throttle_class() for throttle_class in self.throttle_classes]

    def dispatch(self, request, *args, **kwargs):
        for throttle in self.get_throttles():
            if not throttle.allow_request(request, self):
                wait = throttle.wait()
                response = HttpResponse(
                    "Request was throttled. Please try again later.",
                    status=429,
                )
                if wait is not None:
                    response["Retry-After"] = f"{int(wait)}"
                return response

        return super().dispatch(request, *args, **kwargs)
