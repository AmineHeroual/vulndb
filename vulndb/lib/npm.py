"""
NPM Security Advisory to NVD CVE converter

This module implements basic functionality to query npm registry for security advisories
"""
import json
import logging
import re

import requests

import vulndb.lib.config as config
from vulndb.lib.nvd import NvdSource
from vulndb.lib.utils import get_default_cve_data

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)


class NpmSource(NvdSource):
    """
    Npm source
    """

    def bulk_search(self, app_info, pkg_list):
        """
        Bulk search the resource instead of downloading the information

        :param payload: Data containing required metadata and dependencies
        :return: Vulnerability result
        """
        payload = {**app_info}
        requires = {}
        dependencies = {}
        for pkg in pkg_list:
            vendor = ""
            name = ""
            version = ""
            tmpA = pkg.split("|")
            if len(tmpA) == 3:
                vendor = tmpA[0]
            version = tmpA[len(tmpA) - 1]
            name = tmpA[len(tmpA) - 2]
            requires[name] = version
            dependencies[name] = {"version": version}
        payload["requires"] = requires
        payload["dependencies"] = dependencies
        return self.fetch(payload)

    def fetch(self, payload):
        LOG.info("Fetch npm advisory from {}".format(config.npm_url))
        r = requests.post(url=config.npm_url, json=payload)
        json_data = r.json()
        return self.convert(json_data)

    def get_version_ranges(self, version_str):
        """
        Version range formats used by npm
        <1.10.2
        <=4.0.13 || >=4.1.0 <4.1.2
        >=4.0.14 <4.1.0 || >=4.1.2
        :param version_str:
        :return: List of version ranges
        """
        version_list = []
        tmpA = version_str.split("||")
        for ver in tmpA:
            version_start = ""
            ver = ver.strip()
            tmpB = ver.split(" ")
            if tmpB[0].startswith(">"):
                version_start = tmpB[0].replace(">=", "").replace(">", "")
            version_end = tmpB[len(tmpB) - 1].replace("<=", "").replace("<", "")
            version_list.append([version_start, version_end])
        return version_list

    def convert(self, adv_data):
        ret_data = []
        assigner = "@npm"
        for k, v in adv_data.get("advisories").items():
            if v["deleted"]:
                continue
            for cve_id in v.get("cves"):
                publishedDate = v["created"]
                lastModifiedDate = v["updated"]
                description = (
                    v.get("title", "")
                    + "\\n"
                    + v.get("overview", "")
                    + "\\n"
                    + v.get("recommendation", "")
                ).replace("`", "")
                references = [{"name": "npm advisory", "url": v.get("url")}]
                severity = v.get("severity")
                vendor = "npm"
                product = v["module_name"]
                score, severity, vectorString, attackComplexity = get_default_cve_data(
                    severity
                )
                cwe_id = v.get("cwe")
                version = v["vulnerable_versions"]
                version_ranges = self.get_version_ranges(version)
                for ver in version_ranges:
                    tdata = config.CVE_TPL % dict(
                        cve_id=cve_id,
                        cwe_id=cwe_id,
                        assigner=assigner,
                        references=json.dumps(references),
                        description=description,
                        vectorString=vectorString,
                        vendor=vendor,
                        product=product,
                        version="*",
                        version_start=ver[0],
                        version_end=ver[1],
                        severity=severity,
                        attackComplexity=attackComplexity,
                        score=score,
                        publishedDate=publishedDate,
                        lastModifiedDate=lastModifiedDate,
                    )
                    vuln = NvdSource.convert_vuln(json.loads(tdata))
                    ret_data.append(vuln)
        return ret_data
