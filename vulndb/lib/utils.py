import importlib

from vulndb.lib import Severity

from datetime import datetime
from enum import Enum


class ClassNotFoundError(Exception):
    """docstring for ClassNotFoundError"""

    def __init__(self, msg):
        super(ClassNotFoundError, self).__init__(msg)


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


def serialize_vuln_list(datas):
    """Serialize vulnerability data list to help with storage

    :param datas: Data list to store
    :return List of serialized data
    """
    data_list = []
    for data in datas:
        ddata = data
        details = None
        if type(data) != "dict":
            ddata = vars(data)
            details = data.details
        else:
            details = data["details"]
        for vuln_detail in details:
            data_to_insert = ddata.copy()
            data_to_insert["details"] = vuln_detail
            data_list.append(dump(data_to_insert))
    return data_list
