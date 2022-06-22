#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import logging
from io import BytesIO
from typing import Iterable
from zipfile import ZipFile

import requests

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importers.osv import parse_advisory_data

logger = logging.getLogger(__name__)


class PyPIImporter(Importer):
    license_url = "https://github.com/pypa/advisory-database/blob/main/LICENSE"
    spdx_license_expression = "CC-BY-4.0"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        """
        1. Fetch the data from osv api
        2. unzip the file
        3. open the file one by one
        4. yield the json file to parse_advisory_data
        """
        url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
        response = requests.get(url).content
        with ZipFile(BytesIO(response)) as zip_file:
            for file_name in zip_file.namelist():
                if not file_name.startswith("PYSEC-"):
                    logger.error(f"NotImplementedError PyPI package file_name: {file_name}")
                else:
                    with zip_file.open(file_name) as f:
                        vul_info = json.load(f)
                        yield parse_advisory_data(vul_info)
