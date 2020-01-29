from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

import vulndb.lib.config as config
from vulndb.lib import Severity, PackageIssue, VulnerabilityOccurrence
import importlib

from datetime import datetime
from enum import Enum

# Configure tinydb
TinyDB.DEFAULT_TABLE_KWARGS = {"cache_size": 20}

# Index db for faster search
index_db = TinyDB(
    config.vulndb_index,
    sort_keys=False,
    indent=0,
    storage=CachingMiddleware(JSONStorage),
    default_table="index",
)


def load(d):
    """Parses a python object from a JSON string. Every Object which should be loaded needs a constuctor that doesn't need any Arguments.
Arguments: Dict object; the module which contains the class, the parsed object is instance of."""

    def _load(d):
        if isinstance(d, list):
            li = []
            for item in d:
                li.append(_load(item))
            return li
        elif isinstance(d, dict) and "type" in d:  # object
            t = d["type"]
            if t == "datetime":
                return datetime.fromisoformat(d["value"])
            if t == "Severity":
                return Severity.from_str(d["value"])
            try:
                del d["type"]
                clazz = getattr(importlib.import_module("vulndb.lib"), t)
                if hasattr(clazz, "from_dict"):
                    o = clazz.from_dict(d)
                else:
                    o = clazz(**d)
            except KeyError:
                raise ClassNotFoundError(
                    "Class '%s' not found in the given module!" % t
                )
            except TypeError as te:
                print(te)
                raise TypeError(
                    "Make sure there is an constuctor that doesn't take any arguments (class: %s)"
                    % t
                )
            return o
        elif isinstance(d, dict):  # dict
            rd = {}
            for key in d:
                rd[key] = _load(d[key])
            return rd
        else:
            return d

    return _load(d)


def dump(obj):
    """Dumps a python object to a JSON string. Argument: Python object"""

    def _dump(obj, path):
        if isinstance(obj, list):
            li = []
            i = 0
            for item in obj:
                li.append(_dump(item, path + "/[" + str(i) + "]"))
                i += 1
            return li
        elif isinstance(obj, Enum):  # Enum
            d = {}
            d["type"] = obj.__class__.__name__
            d["value"] = obj.value
            return d
        elif isinstance(obj, dict):  # dict
            rd = {}
            for key in obj:
                rd[key] = _dump(obj[key], path + "/" + key)
            return rd
        elif isinstance(obj, datetime):  # datetime
            d = {}
            d["type"] = obj.__class__.__name__
            d["value"] = obj.isoformat()
            return d
        elif (
            isinstance(obj, str)
            or isinstance(obj, int)
            or isinstance(obj, float)
            or isinstance(obj, complex)
            or isinstance(obj, bool)
            or type(obj).__name__ == "NoneType"
        ):
            return obj
        else:
            d = {}
            d["type"] = obj.__class__.__name__
            for key in obj.__dict__:
                d[key] = _dump(obj.__dict__[key], path + "/" + key)
            return d

    return _dump(obj, "/")


class ClassNotFoundError(Exception):
    """docstring for ClassNotFoundError"""

    def __init__(self, msg):
        super(ClassNotFoundError, self).__init__(msg)


def get(table_name="vulndb", db_file=config.vulndb_file):
    """Get database instance

    :param table_name: Table name. Default vulndb
    :param db_file: DB file
    """
    # indent=None will produce the lowest size db file but will increase
    # startup time
    db = TinyDB(
        db_file,
        sort_keys=False,
        indent=0,
        storage=CachingMiddleware(JSONStorage),
        default_table=table_name,
    )
    return db, db.table(table_name)


def store(db, table, datas):
    """Store data in the table

    :param table: Table instance
    :param datas: Data list to store
    """
    data_list = []
    index_list = []
    # Create separate row for each vulnerability detail to help with search
    for data in datas:
        ddata = vars(data)
        for vuln_detail in data.details:
            data_to_insert = ddata.copy()
            data_to_insert["details"] = vuln_detail
            data_list.append(dump(data_to_insert))
            index_list.append(
                {
                    "id": data.id,
                    "name": vuln_detail.package,
                    "version": vuln_detail.max_affected_version,
                }
            )
    # Automatically create an index
    docs = table.insert_multiple(data_list)
    index_db.insert_multiple(index_list)
    # Save the data and the index
    db.storage.flush()
    index_db.storage.flush()
    return docs


def list_all(table):
    """Method to return all data

    :param table: Table instance
    """
    return table.all()


def _test_func(version_attrib, value):
    return value in version_attrib or version_attrib == "*"


def pkg_search(table, name, version):
    """Search for a given package and convert into Vulnerability Occurence

    :param table: Table instance
    :param name: Name of the package
    :param version: Package version

    :return List of vulnerability occurence or none
    """
    try:
        Record = Query()
        datas = table.search(
            (Record.details.package == name)
            & (Record.details.max_affected_version.test(_test_func, version))
        )
        return _parse_results(datas)
    except IndexError:
        return None


def _parse_results(datas):
    """Method to parse raw search result and convert to Vulnerability occurence

    :param datas: Search results from tinydb
    :return List of vulnerability occurence
    """
    data_list = []
    id_list = []
    for d in datas:
        vobj = load(d)
        vdetails = vobj["details"]
        package_type = ""
        cpe_uri = ""
        if isinstance(vdetails, dict):
            package_type = vdetails["package_type"]
            cpe_uri = vdetails["cpe_uri"]
        else:
            package_type = vdetails.package_type
            cpe_uri = vdetails.cpe_uri
        unique_key = vobj["id"] + "|" + package_type
        # Filter duplicates for the same package with the same id
        if unique_key not in id_list:
            occ = VulnerabilityOccurrence(
                id=vobj["id"],
                problem_type=vobj["problem_type"],
                type=package_type,
                severity=vobj["severity"],
                cvss_score=vobj["score"],
                package_issue=PackageIssue(
                    affected_location=cpe_uri, fixed_location=None
                ),
                short_description=vobj["description"],
                long_description=None,
                related_urls=vobj["related_urls"],
                effective_severity=vobj["severity"],
            )
            id_list.append(unique_key)
            data_list.append(occ)
    return data_list


def truncate(db, table_name="vulndb"):
    """Truncate given table in the database

    :param db: Database
    :param table_name: Table name
    """
    return db.purge_table(table_name)
