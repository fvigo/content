import pytest


def load_data(path):
    with open(path, 'r') as f:
        return f.read()


TEST_VECTORS = [
    ('test_data/pandev.pem', '81681aad607e66a1a77c1ad62b1eda0b3e1d0b77f9a2b901dda828d08b412f2f'),
    ('test_data/test2.pem', 'fead39be0bc680baaaf282d915b44c803e7ab66e61ff5afc356bcf0d12d73f2c'),
]


@pytest.mark.parametrize("input, expected", TEST_VECTORS)
def test_case(mocker, input, expected):
    from CertificateValueFromPEM import value_from_pem

    pem = load_data(input)
    assert value_from_pem(pem) == expected
