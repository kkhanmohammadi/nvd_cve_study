from .wfn_converter_2_3 import WFNConverter3
import pandas as pd
import datetime
from packaging import version
import re
import stanza

gbl_cleaning_words_path = 'c:/nvd/cleaning_words.csv'
gbl_stanza_path = 'c:/stanza_resources1'
gbl_nvddir = 'C:/nvd/'
gbl_matched_nvd_cves = 'c:/nvd/matched_nvd_cves.csv'
gbl_matched_assets ='c:/nvd/matched_assets.csv'


def get_main_version(version):
    return version.split('.')[0]


def is_version_any(version):
    main_ver = get_main_version(version)
    return main_ver == '*' or main_ver == 'ANY'


def clean_word(word):
    if word is not None and word != '':
        word = re.sub(pattern=r"[0-9][\w.]+", string=word, repl='')  # remove digits
        word = re.sub(pattern=r"([a-zA-Z]+)(\d+)", string=word, repl=r'\1')  # remove digits from end of the words
        word = re.sub(pattern=r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$", string=word, repl='')  # remove email
        word = re.sub(pattern=r"\(.*?\)", string=word, repl='')  # remove ()
        word = re.sub(pattern=r"\[.*?\]", string=word, repl='')  # remove []
        word = re.sub(pattern=r"\<.*?\>", string=word, repl='')  # remove <>
        word = re.sub(pattern=r"\{.*?\}", string=word, repl='')  # remove {}
        word = re.sub(pattern=r"[-_,;|/]", string=word, repl=' ')  # remove special characters
        word = re.sub(pattern=r"\\", string=word, repl=' ')
        word = re.sub(pattern=r"[\w]+\.$", string=word, repl=' ')  # remove words abrivated like inc.
        word = re.sub(pattern=r"[ ]+", string=word, repl=' ')  # remove extra spaces
        word = word.strip().lower()
        filtering_words = pd.read_csv(gbl_cleaning_words_path , sep=",", header=None)[0:].values.tolist()[0]

        word = ' '.join([w for w in word.split() if w.lower() not in filtering_words])
        # if it is greater than 3 word return first three word
        words = word.split()
        if len(words) > 3:
            return (' '.join(words[0:3]))
        else:
            return (word)
    else:
        return word


class CVEMatcher:

    def __init__(self, df_assets, df_cves):
        self.wfn_converter = WFNConverter3()
        self.df_assets = pd.DataFrame(data=df_assets,
                                      columns=['product', 'vendor', 'version', 'number_of_assets', 'cpes'])
        self.df_cves = pd.DataFrame(data=df_cves, columns=['id', 'summary', 'reference_data', 'cpes',
                                                           'vector', 'attack_complexity', 'confidentiality_impact',
                                                           'integrity_impact', 'availability_impact',
                                                           'privileges_required', 'base_score',
                                                           'base_severity', 'exploitability_score',
                                                           'impact_score', 'cpes_logic'])

        # keep these lines when the data is read from cve need to change str to list
        self.df_cves['cpe_list'] = self.df_cves.apply(lambda x: x['cpes'], axis=1)
        self.df_cve_asset = pd.DataFrame(
            columns=['product', 'vendor', 'version', 'number_of_assets', 'cve_id', 'cve_summary'])
        self.matched_cves = pd.DataFrame()
        stanza.download('en', gbl_stanza_path) # added to use stanza package
        self.nlp = stanza.Pipeline('en', processors='tokenize,pos', dir=gbl_stanza_path)
        self.df_cves['summary_nouns'] = self.df_cves['summary'].apply(lambda x: self.extract_stanza_nouns(x))

    def find_matched_cves_to_assets(self):

        df_assets_c = self.df_assets.copy()
        df_assets_c['cpe_list'] = df_assets_c.apply(lambda x: x['cpes'], axis=1)
        df_assets_c['cpe_list_length'] = df_assets_c.apply(
            lambda x: len(x['cpe_list']) if str(x['cpe_list']) != 'nan' else 0, axis=1)
        df_assets_with_cpe = df_assets_c[df_assets_c['cpe_list_length'] == 1]
        df_assets_without_cpe = df_assets_c[df_assets_c['cpe_list_length'] != 1]

        if not df_assets_without_cpe.empty and not df_assets_with_cpe.empty:
            df_assets_with_cpe['wfn'] = df_assets_with_cpe.apply(lambda x: x['cpe_list'][0].get('wfn'), axis=1)
            df_assets_without_cpe['wfn'] = df_assets_without_cpe.apply(
                lambda x: self.create_wfn_from_software_attributes(x), axis=1)
            df_assets_cpe = pd.concat([df_assets_with_cpe, df_assets_without_cpe], sort=False)
        else:
            if not df_assets_with_cpe.empty:
                df_assets_with_cpe['wfn'] = df_assets_with_cpe.apply(lambda x: x['cpe_list'][0].get('wfn'), axis=1)
                df_assets_cpe = df_assets_with_cpe
            else:
                if not df_assets_without_cpe.empty:
                    df_assets_without_cpe['wfn'] = df_assets_without_cpe.apply(
                        lambda x: self.create_wfn_from_software_attributes(x), axis=1)
                    df_assets_cpe = df_assets_without_cpe

        df_assets_cpe['cves'] = df_assets_cpe.apply(lambda row: self.search_cves_for_wfn(row['wfn']), axis=1)
        df_assets_cpe = df_assets_cpe[df_assets_cpe['cves'].str.len() != 0]

        df_assets_cpe.to_csv(gbl_nvddir + "df_assets_cves.csv")

        if not df_assets_cpe.empty:
            self.matched_assets = df_assets_cpe.copy()
            df_assets_cpe = df_assets_cpe.join(
                df_assets_cpe['cves'].apply(pd.Series).stack().reset_index(1, name='cve')).fillna('').drop('level_1', 1)
            df_applicable_cve = df_assets_cpe.groupby(['cve'])['number_of_assets'].sum()
            df_applicable_cve = df_applicable_cve.reset_index()
            df_applicable_cve.columns = ['id', 'number_of_assets']
            df_applicable_cve = df_applicable_cve.merge(self.df_cves, how='left', on='id')
            self.matched_cves = df_applicable_cve.drop(columns=['cpe_list'])
        else:
            self.matched_cves = pd.DataFrame()
        return

    def save_matched_cves(self):
        yesterday = datetime.date.today() + datetime.timedelta(days=-1)

        # pd.DataFrame.to_gbq(self.matched_cves, 'vulnerability_management.Matched_CVEs' + '_' + str(date),
        #                    project_id='security-integration', if_exists='replace')
        if not self.matched_cves.empty:
            self.matched_cves.to_csv(gbl_matched_nvd_cves)


    def save_matched_assets(self):
        date = datetime.date.today()
        if not self.matched_cves.empty:
            try:
                self.matched_assets['product'] = self.matched_assets['product'].apply(
                    lambda x: re.sub(pattern=r"\x00", string=x, repl=' ') if x!=None else '')
                self.matched_assets['vendor'] = self.matched_assets['vendor'].apply(
                    lambda x: re.sub(pattern=r"\x00", string=x, repl=' ') if x!=None else '')
                self.matched_assets.to_csv(gbl_matched_assets)
            except:
                print(f"Error in encoding data and writing data to csv: {date.strftime('%Y%m%d')}")

        else:
            print(f"Matched_CVEs was empty for data: {date.strftime('%Y%m%d')}")


    def create_wfn_from_software_attributes(self, software):
        v = clean_word(software['vendor'])
        if v is not None and v != '':
            if len(v.split()) > 1:
                v = v.split()[0]
        p = clean_word(software['product'])

        wfn = {'part': 'a', 'vendor': v, 'product': p,
               'version': software['version']}
        return self.wfn_converter.create_wfn_from_user_input(wfn)

    def search_cves_for_wfn(self, wfn):

        df_matched_cve = self.search_cves_by_product_vendor_version(wfn)
        return df_matched_cve['id'].to_list()

    def search_cves_by_product_vendor_version(self, wfn):

        asset_product = wfn.get('product')
        asset_vendor = wfn.get('vendor')
        asset_version = wfn.get('version')
        df_temp_cves = self.df_cves.copy()

        df_temp_cves['result'] = self.df_cves.apply(
            lambda row: True if ((((asset_product, asset_vendor) in self.get_product_vendor_list(row['cpe_list']))
                                  or is_product_in_cve_summary(asset_product, row['summary_nouns']))
                                 and self.is_version_include(row['cpes_logic'], asset_version)) else False, axis=1)

        df_temp_cves = df_temp_cves[df_temp_cves['result'] == True]
        df_temp_cves.drop(columns=['result'], inplace=True)
        return df_temp_cves  # cve_matches

    def get_product_vendor_list(self, uri_binding_list):

        product_vendor_list = [(self.wfn_converter.convert_cpe_uri_to_wfn(x).get('product'),
                                self.wfn_converter.convert_cpe_uri_to_wfn(x).get('vendor')) for x in uri_binding_list]
        return product_vendor_list

    def search_cves_with_summary(self, wfn):
        df_temp_cves = self.df_cves.copy()
        df_temp_cves['result'] = self.df_cves.apply(
            lambda row: True if is_product_and_vendor_in_cve_summary(row, wfn) else False, axis=1)
        df_temp_cves = df_temp_cves[df_temp_cves['result'] == True]
        return df_temp_cves

    def is_version_include(self, cve_cpes_version_logic, asset_cpe_version):

        if is_version_any(asset_cpe_version) or not cve_cpes_version_logic or cve_cpes_version_logic == '[]':
            return True
        else:

            list_all_cpes = re.findall(r'\'cpe23Uri\': \'(cpe:2.3:.[^\']+)\'', str(cve_cpes_version_logic))
            list_start_excluding_end_excluding = re.findall(
                r'\'cpe23Uri\': \'(cpe:2.3:.[^\']+)\', \'versionStartExcluding\': \'(.[^\']+)\', \'versionEndExcluding\': \'(.[^\']+)\'',
                str(cve_cpes_version_logic))
            list_start_excluding_end_including = re.findall(
                r'\'cpe23Uri\': \'(cpe:2.3:.[^\']+)\', \'versionStartExcluding\': \'(.[^\']+)\', \'versionEndIncluding\': \'(.+?)\'',
                str(cve_cpes_version_logic))
            list_start_including_end_excluding = re.findall(
                r'\'cpe23Uri\': \'(cpe:2.3:.[^\']+)\', \'versionStartIncluding\': \'(.[^\']+)\', \'versionEndExcluding\': \'(.+?)\'',
                str(cve_cpes_version_logic))
            list_start_including_end_including = re.findall(
                r'\'cpe23Uri\': \'(cpe:2.3:.[^\']+)\', \'versionStartIncluding\': \'(.[^\']+)\', \'versionEndIncluding\': \'(.+?)\'',
                str(cve_cpes_version_logic))
            list_end_excluding = re.findall(
                r'\'cpe23Uri\': \'(cpe:2.3:.[^\']+)\', \'versionEndExcluding\': \'(.[^\']+)\'',
                str(cve_cpes_version_logic))
            list_end_including = re.findall(
                r'\'cpe23Uri\': \'(cpe:2.3:.[^\']+)\', \'versionEndIncluding\': \'(.[^\']+)\'',
                str(cve_cpes_version_logic))

            for this_cpe in list_all_cpes:
                cve_cpe_version = self.wfn_converter.get_uri_binding_version(this_cpe)
                if not is_version_any(cve_cpe_version):
                    if version.parse(cve_cpe_version) == version.parse(asset_cpe_version):
                        print(f"asset_version:{asset_cpe_version}, cve_version:{cve_cpe_version}")
                        return True

            for (this_cpe, start, end) in list_start_excluding_end_excluding:
                if version.parse(start) < version.parse(asset_cpe_version) and version.parse(end) > version.parse(
                        asset_cpe_version):
                    print(f"asset_version:{asset_cpe_version}, cve_version:{start}-{end}")
                    return True

            for (this_cpe, start, end) in list_start_excluding_end_including:
                if version.parse(start) < version.parse(asset_cpe_version) and version.parse(end) >= version.parse(
                        asset_cpe_version):
                    print(f"asset_version:{asset_cpe_version}, cve_version:{start}-{end}")
                    return True

            for (this_cpe, start, end) in list_start_including_end_excluding:
                if version.parse(start) <= version.parse(asset_cpe_version) and version.parse(end) > version.parse(
                        asset_cpe_version):
                    print(f"asset_version:{asset_cpe_version}, cve_version:{start}-{end}")
                    return True

            for (this_cpe, start, end) in list_start_including_end_including:
                if version.parse(start) <= version.parse(asset_cpe_version) and version.parse(end) >= version.parse(
                        asset_cpe_version):
                    print(f"asset_version:{asset_cpe_version}, cve_version:{start}-{end}")
                    return True

            for (this_cpe, end) in list_end_including:
                if version.parse(end) >= version.parse(asset_cpe_version):
                    print(f"asset_version:{asset_cpe_version}, cve_version_end_include:{end}")
                    return True

            for (this_cpe, end) in list_end_excluding:
                if version.parse(end) > version.parse(asset_cpe_version):
                    print(f"asset_version:{asset_cpe_version}, cve_version_end_exclude:{end}")
                    return True

            return False

    def is_main_version_equal(self, cve_cpes_list, version):
        if is_version_any(version):
            return True
        else:
            for cpe in cve_cpes_list:
                if get_main_version(self.wfn_converter.get_uri_binding_version(cpe)) >= get_main_version(
                        version):
                    return True
        return False

    def extract_stanza_nouns(self, summary):
        summary = ''.join(summary)
        if not summary:
            return []
        else:
            #nlp = stanza.Pipeline('en', processors='tokenize,pos')
            doc = self.nlp(summary)
            nouns = []
            for sentence in doc.sentences:
                for word in sentence.words:
                    print(word.text, word.lemma, word.pos, word.xpos)
                    if word.xpos in ['NN', 'NNS', 'NNP', 'NNPS']:
                        nouns.append(word.text.lower())
            return nouns



def is_product_in_cve_summary(product, summary_nouns):
    if not summary_nouns or not product:
        return False
    else:
        a = True if (set(product.split()).issubset(set(summary_nouns))) else False
        if a:
            print(f'product:{product}')
        return a


def is_product_and_vendor_in_cve_summary(cve, wfn):
    summary_words = get_summary_words(cve)
    return is_word_in_summary(wfn.get('vendor'), summary_words) and is_word_in_summary(wfn.get('product'),
                                                                                       summary_words)


def is_word_in_summary(word, summary_words):
    # if word in summary_words:
    return False if (set(word.split()).intersection(set(summary_words)) is None) else True



def get_summary_words_new(summary):
    summary = ''.join(summary)  # list of strings to string
    if summary == '':
        return []
    else:
        summary = summary.lower()
        summary_words = summary.split()
        return summary_words


def get_summary_words(cve):
    summary = ''.join(cve['summary'])
    if summary == '':
        return []
    else:
        summary = summary.lower()
        summary_words = summary.split()
        return summary_words
