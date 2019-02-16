from urllib.parse import quote, urlencode

import pytest

from tupas_verisigner import TupasVerisigner

ALL_EXPECTED_QUERY_ARG_NAME_TUPLES = (
    ('B02K_VERS',),
    ('B02K_TIMESTMP',),
    ('B02K_IDNBR',),
    ('B02K_STAMP',),
    ('B02K_CUSTNAME',),
    ('B02K_KEYVERS',),
    ('B02K_ALG',),
    ('B02K_CUSTID',),
    ('B02K_CUSTTYPE',),
    ('B02K_MAC',),
)


class TestTupasVerisigner(object):
    @pytest.fixture
    def query_args(self):
        return {
            'B02K_VERS': '0003',
            'B02K_TIMESTMP': '50020181017141433899056',
            'B02K_IDNBR': '2512408990',
            'B02K_STAMP': '20010125140015123456',
            'B02K_CUSTNAME': 'VÄINÖ MÄKI',
            'B02K_KEYVERS': '0001',
            'B02K_ALG': '03',
            'B02K_CUSTID': '9984',
            'B02K_CUSTTYPE': '02',
            'B02K_MAC': (
                '88AAF3CE995A7887935A50B0F483C4FB'
                '35D908D6ABC8BADDB9B4C0C30416275D'
            ),
        }

    @pytest.fixture
    def error_url(self):
        return 'http://otherserver.com/error.html'

    @pytest.fixture
    def signer(self, error_url):
        return TupasVerisigner(
            'inputsecret',
            'outputsecret',
            'http://otherserver.com',
            error_url,
            encoding='Windows-1252',
        )

    @pytest.fixture
    def output_url_for_valid_signature(self):
        return (
            'http://otherserver.com/?firstname=V%C3%A4in%C3%B6&lastname=M%C3%'
            'A4ki&hash=0cde0ea2e3afd5b7679bd89f64e1e0a7caee4232dbd747d4a6dc9c'
            '42023262ab'
        )

    def _get_input_url(self, query_args):
        return 'http://someserver.com/?{query_string}'.format(
            query_string=urlencode(
                query_args, encoding='Windows-1252', quote_via=quote
            ),
        )

    def test_returns_correct_output_url_when_signature_value(
        self, signer, query_args, output_url_for_valid_signature
    ):
        assert (
            signer.verify_and_sign_url(self._get_input_url(query_args)) ==
            output_url_for_valid_signature
        )

    @pytest.mark.parametrize(
        ('arg_name_to_remove',),
        ALL_EXPECTED_QUERY_ARG_NAME_TUPLES
    )
    def test_returns_error_url_when_bad_input_query_argument_missing(
        self, signer, query_args, arg_name_to_remove, error_url
    ):
        del query_args[arg_name_to_remove]
        assert (
            signer.verify_and_sign_url(self._get_input_url(query_args)) ==
            error_url
        )

    @pytest.mark.parametrize(
        ('arg_name_to_empty',),
        ALL_EXPECTED_QUERY_ARG_NAME_TUPLES
    )
    def test_returns_error_url_when_bad_input_query_argument_empty(
        self, signer, query_args, arg_name_to_empty, error_url
    ):
        query_args[arg_name_to_empty] = ''
        assert (
            signer.verify_and_sign_url(self._get_input_url(query_args)) ==
            error_url
        )

    def test_returns_error_url_when_signature(
        self, signer, query_args, error_url
    ):
        query_args['B02K_MAC'] = 'garbage'
        assert (
            signer.verify_and_sign_url(self._get_input_url(query_args)) ==
            error_url
        )
