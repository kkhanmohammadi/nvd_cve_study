import ast

import numpy as np

from .cpe_set_operations import calculate_symmetric_difference_between_two_cpe_lists


# todo None of this has proper documentation

def sort_cpes_by_version(cpes, software_version):
    """
    sort the cpes based on version's order, all cpes relate to a software. it checks if the version is year, sort by
    year, if not sort by version prefix
    :param cpes:
    :param software_version: version of a software
    :return: return cpes
    """
    version_prefixes = create_version_prefixes(software_version)
    if len(version_prefixes) > 0:
        return sort_cpes_by_version_prefixes(cpes, version_prefixes)
    if is_year(software_version):
        return sort_cpes_by_year_version(cpes, software_version)
    return cpes


def find_cpes_by_version(cpes, software_version):
    """
    find a cpe in cpes which has similar version like software_version
    :param cpes:
    :param software_version:
    :return: (true,exact_cpe) or (false,null)
    """
    exact_candidates = []
    if software_version != '':
        for cpe in cpes:
            cpe_version = get_cpe_version(cpe)
            if cpe_version == software_version:
                exact_candidates.append(cpe)
                return True, exact_candidates
    return False, exact_candidates


def sort_cpes_by_version_prefixes(cpes, version_prefixes):
    """
    sort cpes by their version
    # Example:
    # version = 4.7.2-3
    # version_prefixes = [4, 4.7, 4.7.2-3]
    :param cpes:
    :param version_prefixes:
    :return: sorted cpes
    """

    sorted_cpes = []
    for prefix in version_prefixes:
        for cpe in cpes:
            cpe_version = get_cpe_version(cpe)
            if has_prefix(prefix, cpe_version) and not_in_sorted_list(cpe, sorted_cpes):
                sorted_cpes.append(cpe)
    # Kobra: if not found cpe with prefix version
    if not sorted_cpes:
        unsorted_cpes = calculate_symmetric_difference_between_two_cpe_lists(sorted_cpes, cpes)
        sorted_cpes.extend(unsorted_cpes)
    return sorted_cpes


def sort_cpes_by_year_version(cpes, software_version):
    """
    for cpes which version is based on year, sort them by year
    :param cpes: cpes
    :param software_version: which is year
    :return: sorted cpes
    """
    sorted_cpes = []
    cpes_year_not_equal = []
    for cpe in cpes:
        cpe_version = get_cpe_version(cpe)
        if cpe_version == software_version:
            sorted_cpes.append(cpe)
        elif str(cpe_version).isdigit():
            cpes_year_not_equal.append(cpe)
    sorted_cpes.extend(cpes_year_not_equal)
    if not sorted_cpes:
        unsorted_cpes = calculate_symmetric_difference_between_two_cpe_lists(sorted_cpes, cpes)
        sorted_cpes.extend(unsorted_cpes)
    return sorted_cpes


def sort_cpes_by_operating_system(cpes, os):
    """
    sort cpe based on os version
    :param cpes:
    :param os:
    :return:
    """
    sorted_cpes = []
    for cpe in cpes:
        cpe_target_software = get_cpe_target_sw(cpe)
        if is_same_os(cpe_target_software, os) and not_in_sorted_list(cpe, sorted_cpes):
            if len(cpe_target_software) == len(os):
                sorted_cpes.insert(0, cpe)
            else:
                sorted_cpes.append(cpe)
    if not sorted_cpes:
        unsorted_cpes = calculate_symmetric_difference_between_two_cpe_lists(sorted_cpes, cpes)
        sorted_cpes.extend(unsorted_cpes)
    return sorted_cpes


def create_version_prefixes(software_version):
    """
    split the version to find the prefix of the version
    :param software_version:
    :return:
    """
    version_elements = str(software_version).split('.')
    if len(version_elements) > 1:
        prefixes = [version_elements[0]]
        for i in range(1, len(version_elements)):
            prefixes.append(prefixes[i - 1] + '.' + str(version_elements[i]))
        prefixes = list(reversed(prefixes))
        return prefixes
    return []


def has_prefix(version_prefix, uri_binding_version):
    """
    check version is in format x.y.z
    :param version_prefix:
    :param uri_binding_version:
    :return:
    """
    return version_prefix in uri_binding_version and version_prefix[0] == uri_binding_version[0]


def is_same_os(uri_binding_os, os):
    return (uri_binding_os in os) or (os in uri_binding_os)


def not_in_sorted_list(uri_binding, sorted_uri_bindings):
    return not sorted_uri_bindings.__contains__(uri_binding)


def is_nan(x):
    return x is np.nan or x != x


def is_year(software_version):
    if software_version is None:
        return False
    return len(software_version) == 4 and str(software_version).isdigit()


def get_cpe_version(cpe):
    wfn_version = ast.literal_eval(str(cpe.get('wfn')))
    return wfn_version.get('version')


def get_cpe_target_sw(cpe):
    wfn_target_sw = cpe.get('wfn')#ast.literal_eval(cpe.get('wfn'))
    return wfn_target_sw.get('target_sw')
