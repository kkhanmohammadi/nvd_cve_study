import gbls
import pandas as pd
import logging
from wfn.wfn_converter_2_3 import WFNConverter3
import geotab


class FormatCpe(object):
    """
    create formatted cpe name of cpes.
    return formatted cpe dataframe
    """

    # def __init__(self,a):
    #     self.a=a
    #     geotab.logger.logit(2,'\n\nInitializing FormatCpe class\n\n')

    # cpe 2.3 is saved in 'formatted_string'
    def format_cpe_df(self, cpe_dic):
        cpe_df = pd.DataFrame(columns=['uri', 'wfn', 'formatted_string'])
        # sample uri: cpe:/a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~
        # sample formatted_strinng: cpe:2.3:a:\$0.99_kindle_books_project:\$0.99_kindle_books:6:*:*:*:*:android:*:*
        cpe_df[['uri', 'formatted_string']] = cpe_dic[['@name', 'cpe23-item-name']]
        # sample wfn: {'part': 'a', 'vendor': '$0.99_kindle_books_project', 'product': '$0.99_kindle_books', 'version': '6', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'android', 'target_hw': 'ANY', 'other': 'ANY'}
        cpe_df['wfn'] = cpe_dic['cpe23-item-name'].map(lambda x: WFNConverter3().convert_cpe_uri_to_wfn(x))
        geotab.logger.logit(2,'Formatted a cpe dictionary')
        return cpe_df.copy()
