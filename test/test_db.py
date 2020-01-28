import vulndb.lib.db as db
from vulndb.lib.nvd import NvdSource
from vulndb.lib.gha import GitHubSource

import os

import json
import pytest

import tempfile


@pytest.fixture
def test_db():
    with tempfile.NamedTemporaryFile(delete=True) as fp:
        return db.get(table_name="testdb", db_file=fp.name)


@pytest.fixture
def test_vuln_data():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "cve_data.json"
    )
    with open(test_cve_data, "r") as fp:
        json_data = json.loads(fp.read())
        nvdlatest = NvdSource()
        return nvdlatest.convert(json_data)


@pytest.fixture
def test_gha_data():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "gha_data.json"
    )
    with open(test_cve_data, "r") as fp:
        json_data = json.loads(fp.read())
        ghalatest = GitHubSource()
        return ghalatest.convert(json_data)[0]


def test_create(test_db, test_vuln_data):
    docs = db.store(test_db[0], test_db[1], test_vuln_data)
    assert len(docs) > len(test_vuln_data)


def test_search(test_db, test_vuln_data):
    table = test_db[1]
    docs = db.list_all(table)
    assert len(docs) == 0
    docs = db.store(test_db[0], table, test_vuln_data)
    assert len(docs) > 0
    all_data = db.list_all(table)
    assert all_data
    for d in all_data:
        res = db.pkg_search(
            table, d["details"]["package"], d["details"]["max_affected_version"]
        )
        assert len(res)


def test_gha_create(test_db, test_gha_data):
    docs = db.store(test_db[0], test_db[1], test_gha_data)
    assert len(docs) > len(test_gha_data)


def test_gha_search(test_db, test_gha_data):
    table = test_db[1]
    docs = db.list_all(table)
    assert len(docs) == 0
    docs = db.store(test_db[0], table, test_gha_data)
    assert len(docs) > 0
    all_data = db.list_all(table)
    assert all_data
    for d in all_data:
        res = db.pkg_search(
            table, d["details"]["package"], d["details"]["max_affected_version"]
        )
        assert len(res)
