from .encoding import Encoder

# todo none of this has proper documentation


def convert_wfn_to_uri(this_wfn):
    uri = 'cpe:2.3:a:' + ':'.join([Encoder.encode_non_alphanumeric_characters(this_wfn.get('vendor')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('product')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('version')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('update')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('edition')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('language')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('sw_edition')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('target_sw')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('target_hw')),
                                   Encoder.encode_non_alphanumeric_characters(this_wfn.get('other'))])
    uri = uri.replace(':ANY', ':*')
    uri = uri.replace(':NA', ':-')
    return uri


class WFNConverter3:

    def __init__(self):
        self.wfn_doc = {}
        self.wfn_keys = ['part', 'vendor', 'product', 'version', 'update', 'edition', 'language', 'sw_edition',
                         'target_sw', 'target_hw', 'other']

    def convert_cpe_uri_to_wfn(self, cpe_uri):
        self.set_wfn_default_values()
        cpe_uri = self.encode_cpe_uri(cpe_uri)
        wfn_values = self.get_wfn_values_from_cpe_uri(cpe_uri)
        self.set_wfn_values(wfn_values)
        return self.wfn_doc

    def set_wfn_default_values(self):
        self.wfn_doc = {'part': 'ANY', 'vendor': 'ANY', 'product': 'ANY', 'version': 'ANY', 'update': 'ANY',
                        'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'ANY',
                        'target_hw': 'ANY', 'other': 'ANY'}

    @staticmethod
    def encode_cpe_uri(cpe_uri):
        cpe_uri = Encoder.encode_escaped_double_points(cpe_uri)
        cpe_uri = Encoder.encode_escaped_tildes(cpe_uri)  # no need for cpe2.3
        return cpe_uri

    @staticmethod
    def get_wfn_values_from_cpe_uri(cpe_uri):
        wfn_values = WFNConverter3.get_wfn_parts(cpe_uri)
        wfn_values = WFNConverter3.clean_values(wfn_values)
        return wfn_values

    @staticmethod
    def clean_values(values):
        if 'cpe' in values:
            values.remove('cpe')  # discard 'cpe' value
        if '2.3' in values:
            values.remove('2.3')  # discard '2.3' value
        values = [word.replace('*', 'ANY') for word in values]
        values = [word.replace('-', 'NA') for word in values]
        return values

    @staticmethod
    def get_wfn_parts(cpe_uri):
        parts = cpe_uri.split(':')
        return parts

    def set_wfn_values(self, wfn_values):
        self.wfn_doc = {self.wfn_keys[i]: wfn_values[i] for i in range(len(wfn_values))}


    def set_wfn_value(self, key, value):
        if not self.is_value_any(value):
            if value == '*':
                self.wfn_doc.__setitem__(key, 'ANY')
            if value == '-':
                self.wfn_doc.__setitem__(key, 'NA')
            else:
                self.wfn_doc.__setitem__(key, value)

    @staticmethod
    def is_value_any(value):
        return value == '' or value == '*' or value == 'ANY'

    def get_uri_binding_version(self, uri_binding):
        return self.convert_cpe_uri_to_wfn(uri_binding).get('version')

    def get_uri_binding_target_sw(self, uri_binding):
        return self.convert_cpe_uri_to_wfn(uri_binding).get('target_sw')

    def create_wfn_from_user_input(self, user_input):
        self.set_wfn_default_values()
        for key in self.wfn_keys:
            value = dict(user_input).get(key)
            if value is not None and value != '':
                self.set_wfn_value(key, value)
        return self.wfn_doc


