import ast
import datetime
import pandas as pd

from matching import cpe_sorter
from matching.search_terms_generator import generate_product_search_terms
from matching.search_terms_generator import generate_vendor_filters
from matching.search_terms_generator import remove_version_from_search_terms
from matching.software_formatter import FormattedSoftware
import gbls
import sys
import geotab


def find_exact_cpe(candidates, version, product_search_terms):
    found, exact_candidates = cpe_sorter.find_cpes_by_version(candidates.to_dict('records'), version)
    if found:
        return True, exact_candidates

    if 'jdk' in product_search_terms or 'jre' in product_search_terms:
        version = '1.' + version
        found, exact_candidates = cpe_sorter.find_cpes_by_version(candidates.to_dict('records'), version)
        if found:
            return True, exact_candidates

    return False, []


def filter_cpe_candidates_by_vendor(candidates, vendor):
    vendors_prefix = generate_vendor_filters(vendor)
    filtered_candidate = candidates[candidates['vendor'].isin(vendors_prefix)]
    return filtered_candidate


class OrgInventory(object):

    def set_cpe_dictionary(self, cpe_dic):
        self.cpe_dictionary = cpe_dic

    def __init__(self, cpe_dic):


        self.cpe_dictionary = pd.DataFrame(data=cpe_dic, columns=['uri', 'wfn', 'formatted_string'])
        # add two columns for process the similarity

        self.cpe_dictionary['product'] = self.cpe_dictionary.apply(
            lambda x: ast.literal_eval(str(x['wfn'])).get('product'), axis=1)
        self.cpe_dictionary['vendor'] = self.cpe_dictionary.apply(
            lambda x: ast.literal_eval(str(x['wfn'])).get('vendor'), axis=1)


        self.df_assets = pd.DataFrame(columns=['product', 'vendor', 'version', 'NumberOfAssets'])

    def save_assets(self):
        self.df_assets.to_csv(gbls.nvddir + gbls.df_assets_cpe_csv, index=False)
        self.df_assets.to_pickle(gbls.nvddir + gbls.df_assets_cpe_pck)

    def load(self, mypck=None):
        """Load NvdCve vulnerability dataframe that was previously saved."""

        if mypck is None:
            mypck = gbls.df_assets_cpe_pck

        self.df_assets = pd.read_pickle(mypck)
        return None

    def get_assets(self):
        return self.df_assets.copy()

    def update_assets_list(self):

        df_temp =pd.read_csv(gbls.org_inventory)
        self.df_assets[['product', 'vendor', 'version', 'number_of_assets']] = df_temp[
            ['Name', 'Publisher', 'Version', 'NumberOfAssets']]

    def format_assets(self):
        try:
            self.df_assets['cpes'] = self.df_assets.apply(lambda x: self.search_cpes_for_software(x), axis=1)
        except Exception as e:
            print(e)
            self.df_assets.to_csv(gbls.nvddir +'org_assets_cpes_part.csv')

    def search_cpes_for_software(self, software):
        formatted_sw = FormattedSoftware(software)
        product_search_terms = generate_product_search_terms(formatted_sw.product, formatted_sw.vendor)
        version = formatted_sw.get_version(product_search_terms)
        product_search_terms = remove_version_from_search_terms(product_search_terms, version)
        candidates = self.search_cpe_candidates_by_product(product_search_terms)
        filtered_candidates = filter_cpe_candidates_by_vendor(candidates, formatted_sw.vendor)
        found_exact, exact_candidates = find_exact_cpe(filtered_candidates, version, product_search_terms)
        if found_exact:
            return exact_candidates
        else:
            ordered_candidates = filtered_candidates.to_dict('records')
            return ordered_candidates

    def search_cpe_candidates_by_product(self, product_search_terms):
        try:
            candidates = self.cpe_dictionary[self.cpe_dictionary['product'].isin(product_search_terms)]
            return candidates
        except Exception as e:
            print(e)