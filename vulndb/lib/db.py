from sortedcontainers import SortedSet

from vulndb.lib import PackageIssue, VulnerabilityOccurrence
import vulndb.lib.config as config
from vulndb.lib.utils import load, dump, serialize_vuln_list
import vulndb.lib.storage as storage

index_data = None


def get(db_file=config.vulndb_bin_file, index_file=config.vulndb_bin_index):
    """Get database instance

    :param db_file: DB file
    :param index_file: Index file
    """
    global index_data
    index_data = storage.stream_read(index_file)
    return {"db_file": db_file, "index_file": index_file}


def store(db, datas):
    """Store data in the table

    :param table: Table instance
    :param datas: Data list to store
    """
    global index_data
    docs = storage.store(datas, db_file=db["db_file"], index_file=db["index_file"])
    # Re-read the index
    index_data = storage.stream_read(db["index_file"])
    return docs


def list_all(db):
    """Method to return all data

    :param db: db instance
    """
    return storage.stream_read(db["db_file"])


def _key_func(data):
    """Test function for package search

    :param version_attrib: Version value from the db
    :param value: Value to compare against
    """
    if isinstance(data, dict):
        return (
            data["details"]["package"] + "|" + data["details"]["max_affected_version"]
        )
    return data.details.package + "|" + data.details.max_affected_version


def bulk_index_search(pkg_list):
    """
    """
    index_set = SortedSet([ele["name"] + "|" + ele["version"] for ele in index_data])
    pkg_set = SortedSet([ele["name"] + "|" + ele["version"] for ele in pkg_list])
    pkg_set = pkg_set.union(SortedSet([ele["name"] + "|*" for ele in pkg_list]))
    return index_set.intersection(pkg_set)


def index_search(name, version):
    """Search the index for the given package name and version

    :param name: Name of the package
    :param version: Package version

    :return boolean True if the package should be found on the main database. False otherwise.
    """
    try:
        datas = bulk_index_search([{"name": name, "version": version}])
        return len(datas) > 0
    except IndexError:
        return False


def pkg_search(db, name, version):
    """Search for a given package and convert into Vulnerability Occurence

    :param db: db instance
    :param name: Name of the package
    :param version: Package version

    :return List of vulnerability occurence or none
    """
    datas = storage.stream_bulk_search(
        [name + "|" + version], _key_func, db_file=db["db_file"]
    )
    return _parse_results(datas)


def pkg_bulk_search(db, pkg_key_list):
    """Bulk search for a given package and convert into Vulnerability Occurence

    :param db: db instance
    :param pkg_key_list: List of package name|version keys

    :return List of vulnerability occurence or none
    """
    datas = storage.stream_bulk_search(pkg_key_list, _key_func, db_file=db["db_file"])
    return _parse_results(datas)


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
        unique_key = vobj["id"] + "|" + cpe_uri
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
