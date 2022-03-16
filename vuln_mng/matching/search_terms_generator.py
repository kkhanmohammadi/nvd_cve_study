from copy import copy

# import editdistance
import edit_distance

def generate_product_search_terms(product, vendor):
    """
    create a search tearm for product which are more than one word.
    for example product:"windows xp", vendor:"Microsoft" will return all permutaion of three word, windoes, xp,microsoft
    :param product: string name of product
    :param vendor: string name of vendor
    :return: array of search tearm
    """
    if product != '':
        search_terms = split(product)
        search_terms_no_vendor = remove_vendor_from_product_search_terms(copy(search_terms), vendor)
        composed_search_terms_no_vendor = generate_composed_search_terms(search_terms_no_vendor)
        composed_search_terms = generate_composed_search_terms(search_terms)
        composed_search_terms = list(set(composed_search_terms_no_vendor + composed_search_terms))
        composed_search_terms = order_search_terms_by_length(composed_search_terms)
        search_terms = remove_terms_with_less_than_three_chars(search_terms)
        search_terms = order_search_terms_by_length(search_terms)
        search_terms = composed_search_terms + search_terms
        search_terms = add_java_search_terms(search_terms, product)
        return search_terms
    return []


def add_java_search_terms(search_terms, product):
    """
    for search tearm include specif names like java, it add other search term like jre.
    :param search_terms:
    :param product:
    :return:
    """
    if 'java' in product:
        search_terms.insert(0, 'jre')
        if 'development_kit' in product:
            search_terms.insert(0, 'jdk')
            return search_terms
    return search_terms


def generate_vendor_filters(vendor):
    """
    split the name of vendor if it is more than one word
    :param vendor:
    :return:
    """
    if vendor != '' or vendor != 'none':
        search_terms = split(vendor)
        # print(vendor)
        composed_search_terms = generate_composed_search_terms(search_terms)
        search_terms = order_search_terms_by_length(search_terms)
        return composed_search_terms + search_terms
    return []


def split(string):
    return str(string).split('_')


def remove_vendor_from_product_search_terms(search_terms, vendor):
    """
    remove the terms which contains vendor
    :param search_terms:
    :param vendor:
    :return:
    """
    vendor_elements = split(vendor)
    for vendor_element in vendor_elements:
        if vendor_element in search_terms:
            search_terms.remove(vendor_element)
    return search_terms


def generate_composed_search_terms(search_terms):
    """
    create composed of other one word search terms
    :param search_terms:
    :return:
    """
    limit = get_composed_search_terms_limit(search_terms)
    if limit > 0:
        composed_search_terms = []
        composed_search_term = search_terms[0]
        for i in range(limit):
            composed_search_term += '_' + search_terms[i + 1]
            composed_search_terms.insert(0, composed_search_term)
        return composed_search_terms
    return []


def remove_terms_with_less_than_three_chars(search_terms):
    cleaned_search_terms = []
    for search_phrase in search_terms:
        if len(search_phrase) > 2:
            cleaned_search_terms.append(search_phrase)
    return cleaned_search_terms


def order_search_terms_by_length(search_terms):
    search_terms.sort(key=lambda s: len(s))
    search_terms.reverse()
    return search_terms


def get_composed_search_terms_limit(search_terms):
    st_len = len(search_terms)
    if st_len > 0:
        return st_len - 1
    else:
        return 0


def remove_version_from_search_terms(search_terms, version):
    if version in search_terms:
        search_terms.remove(version)
    return search_terms


def are_strings_similar(string_a, string_b):
    #e = editdistance.eval(string_a, string_b)
    e = edit_distance.SequenceMatcher(a=string_a, b=string_b).distance()
    print('e:')
    print(e)
    if len(string_a) > 5:
        return e <= 2
    else:
        return e <= 1
