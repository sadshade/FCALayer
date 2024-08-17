#!/usr/bin/env python3

"""
make-p12

Утилита для создания невалидных сертификатов НУЦ РК по различным шаблонам:
- Сертификат физического лица для аутентификации (AUTH_RSA256_*.p12)
- Сертификат физического лица для подписи (RSA256_*.p12)
- Сертификат юридического лица для аутентификации (AUTH_RSA256_*.p12)

Установка зависимостей Python 3.10+: pip install -r requirements.txt

The software is written for educational purposes only. Use only if you have permission of the owner
Программное обеспечение написано только для образовательных целей. Используйте только с разрешения владельца

Copyright (c) 2023 Konstantin Burov. All rights reserved.
This work is licensed under the terms of the MIT license.
For a copy, see <https://opensource.org/licenses/MIT>.

https://github.com/sadshade/FCALayer/
"""

import re
import os
import base64
import sys
import getopt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder as asn1decoder
from pyasn1.codec.der import encoder as asn1encoder
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

#  Шаблон сертификата X.509 для физического лица
IND_CERT_AUTH: str = """
MIIGVTCCBD2gAwIBAgIUOo7keDU4mX/KewnAlVWyiq8KlO8wDQYJKoZIhvcNAQELBQAwUjELMAkGA1UEBhMCS1oxQzBBBgNV
BAMMOtKw0JvQotCi0KvSmiDQmtCj05jQm9CQ0J3QlNCr0KDQo9Co0Ksg0J7QoNCi0JDQm9Cr0pogKFJTQSkwHhcNMjMxMDI0MDM0NzA4WhcNMjQxMDIzMDM0
NzA4WjB0MR4wHAYDVQQDDBXQmNC80Y8g0KTQsNC80LjQu9C40Y8xCzAJBgNVBAQMAm5vMRgwFgYDVQQFEw9JSU4xMTExMTExMTExMTExCzAJBgNVBAYTAkta
MQswCQYDVQQqDAJubzERMA8GCSqGSIb3DQEJARYCbm8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVY0797mzvqbhObsIRepFcZXQCak3l8YGP
brXkTm3UodwOF5zARFniVYtGS1UA7FgrLaIEIzw3HrD6YidcGd1vsE4cUiPyGY6XWEZQ6pdHhw0J++Z6qVS0aGPRJR28FeVuDRK+bqJztrH1+isft/HYSdn4
FVENrlLauh+EPBfcJ0XUsojPJx5RbWV7d0tUlgfq76M1j/jdSTdm4ToBUwIw9nslk+L+qEKVjz7tDv6SlLr39eXQCaFvCM7QakUeuL9TB/wNZwSQ+psxUKxQ
KppTyBoLkQ8cD8hgRdCZ4ek0oGiudls0/KF6JoQnLAjUyKT75pMtkrWzi/HTmhmzbTTBAgMBAAGjggH/MIIB+zAoBgNVHSUEITAfBggrBgEFBQcDAgYIKoMO
AwMEAQEGCSqDDgMDBAMCATBeBgNVHSAEVzBVMFMGByqDDgMDAgQwSDAhBggrBgEFBQcCARYVaHR0cDovL3BraS5nb3Yua3ovY3BzMCMGCCsGAQUFBwICMBcM
FWh0dHA6Ly9wa2kuZ292Lmt6L2NwczBXBgNVHR8EUDBOMEygSqBIhiFodHRwOi8vY3JsLnBraS5nb3Yua3ovbmNhX3JzYS5jcmyGIyBodHRwOi8vY3JsMS5w
a2kuZ292Lmt6L25jYV9yc2EuY3JsMA4GA1UdDwEB/wQEAwIFoDBiBggrBgEFBQcBAQRWMFQwLgYIKwYBBQUHMAKGImh0dHA6Ly9wa2kuZ292Lmt6L2NlcnQv
bmNhX3JzYS5jZXIwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnBraS5nb3Yua3owWgYDVR0uBFMwUTBPoE2gS4YjaHR0cDovL2NybC5wa2kuZ292Lmt6L25j
YV9kX3JzYS5jcmyGJGh0dHA6Ly9jcmwxLnBraS5nb3Yua3ovbmNhX2RfcnNhLmNybDAdBgNVHQ4EFgQUJsTElpjhMNFwQ5oFegl5aoEowIUwDwYDVR0jBAgw
BoAEW2p0ETAWBgYqgw4DAwUEDDAKBggqgw4DAwUBATANBgkqhkiG9w0BAQsFAAOCAgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
"""

#  Шаблон сертификата X.509 для физического лица для подписи (RSA_*.p12)
IND_CERT_SIGN: str = """MIIGVDCCBDygAwIBAgIUOo7keDU4mX/KewnAlVWyiq8KlO8wDQYJKoZIhvcNAQELBQAwUjELMAkGA1UEBhMCS1oxQzBBBgNVBAMMO
tKw0JvQotCi0KvSmiDQmtCj05jQm9CQ0J3QlNCr0KDQo9Co0Ksg0J7QoNCi0JDQm9Cr0pogKFJTQSkwHhcNMjMxMDI0MDM0NzA4WhcNMjQxMDIzMDM0NzA4W
jB0MR4wHAYDVQQDDBXQmNC80Y8g0KTQsNC80LjQu9C40Y8xCzAJBgNVBAQMAm5vMRgwFgYDVQQFEw9JSU4xMTExMTExMTExMTExCzAJBgNVBAYTAktaMQswC
QYDVQQqDAJubzERMA8GCSqGSIb3DQEJARYCbm8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVY0797mzvqbhObsIRepFcZXQCak3l8YGPbrXkT
m3UodwOF5zARFniVYtGS1UA7FgrLaIEIzw3HrD6YidcGd1vsE4cUiPyGY6XWEZQ6pdHhw0J++Z6qVS0aGPRJR28FeVuDRK+bqJztrH1+isft/HYSdn4FVENr
lLauh+EPBfcJ0XUsojPJx5RbWV7d0tUlgfq76M1j/jdSTdm4ToBUwIw9nslk+L+qEKVjz7tDv6SlLr39eXQCaFvCM7QakUeuL9TB/wNZwSQ+psxUKxQKppTy
BoLkQ8cD8hgRdCZ4ek0oGiudls0/KF6JoQnLAjUyKT75pMtkrWzi/HTmhmzbTTBAgMBAAGjggH+MIIB+jAOBgNVHQ8BAf8EBAMCBsAwKAYDVR0lBCEwHwYIK
wYBBQUHAwQGCCqDDgMDBAEBBgkqgw4DAwQDAgEwXgYDVR0gBFcwVTBTBgcqgw4DAwIDMEgwIQYIKwYBBQUHAgEWFWh0dHA6Ly9wa2kuZ292Lmt6L2NwczAjB
ggrBgEFBQcCAjAXDBVodHRwOi8vcGtpLmdvdi5rei9jcHMwVgYDVR0fBE8wTTBLoEmgR4YhaHR0cDovL2NybC5wa2kuZ292Lmt6L25jYV9yc2EuY3JshiJod
HRwOi8vY3JsMS5wa2kuZ292Lmt6L25jYV9yc2EuY3JsMFoGA1UdLgRTMFEwT6BNoEuGI2h0dHA6Ly9jcmwucGtpLmdvdi5rei9uY2FfZF9yc2EuY3JshiRod
HRwOi8vY3JsMS5wa2kuZ292Lmt6L25jYV9kX3JzYS5jcmwwYgYIKwYBBQUHAQEEVjBUMC4GCCsGAQUFBzAChiJodHRwOi8vcGtpLmdvdi5rei9jZXJ0L25jY
V9yc2EuY2VyMCIGCCsGAQUFBzABhhZodHRwOi8vb2NzcC5wa2kuZ292Lmt6MB0GA1UdDgQWBBQmxMSWmOEw0XBDmgV6CXlqgSjAhTAPBgNVHSMECDAGgARba
nQRMBYGBiqDDgMDBQQMMAoGCCqDDgMDBQEBMA0GCSqGSIb3DQEBCwUAA4ICAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAA=="""

#  Шаблон сертификата X.509 для юридического лица
ENT_CERT_AUTH: str = """
MIIHRzCCBS+gAwIBAgIUOo7keDU4mX/KewnAlVWyiq8KlO8wDQYJKoZIhvcNAQELBQAwgc4xCzAJBgNVBAYTAktaMRUwEwYD
VQQHDAzQkNCh0KLQkNCd0JAxFTATBgNVBAgMDNCQ0KHQotCQ0J3QkDFMMEoGA1UECgxD0KDQnNCaIMKr0JzQldCc0JvQldCa0JXQotCi0IbQmiDQotCV0KXQ
ndCY0JrQkNCb0KvSmiDSmtCr0JfQnNCV0KLCuzFDMEEGA1UEAww60rDQm9Ci0KLQq9KaINCa0KPTmNCb0JDQndCU0KvQoNCj0KjQqyDQntCg0KLQkNCb0KvS
miAoUlNBKTAeFw0yMzA4MzEwODE3NDdaFw0yNDA4MzAwODE3NDdaMIIBEDEeMBwGA1UEAwwV0JjQnNCvINCk0JDQnNCY0JvQmNCvMRcwFQYDVQQEDA7QpNCQ
0JzQmNCb0JjQrzEYMBYGA1UEBRMPSUlOMTExMTExMTExMTExMQswCQYDVQQGEwJLWjEVMBMGA1UEBwwM0JDQodCi0JDQndCQMRUwEwYDVQQIDAzQkNCh0KLQ
kNCd0JAxKjAoBgNVBAoMIdCd0JDQl9CS0JDQndCY0JUg0JrQntCc0J/QkNCd0JjQmDEYMBYGA1UECwwPQklOMjIyMjIyMjIyMjIyMRkwFwYDVQQqDBDQntCi
0KfQldCh0KLQktCeMR8wHQYJKoZIhvcNAQkBFhB1c2VyQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1WNO/e5s76m4Tm7C
EXqRXGV0AmpN5fGBj2615E5t1KHcDhecwERZ4lWLRktVAOxYKy2iBCM8Nx6w+mInXBndb7BOHFIj8hmOl1hGUOqXR4cNCfvmeqlUtGhj0SUdvBXlbg0Svm6i
c7ax9forH7fx2EnZ+BVRDa5S2rofhDwX3CdF1LKIzyceUW1le3dLVJYH6u+jNY/43Uk3ZuE6AVMCMPZ7JZPi/qhClY8+7Q7+kpS69/Xl0AmhbwjO0GpFHri/
Uwf8DWcEkPqbMVCsUCqaU8gaC5EPHA/IYEXQmeHpNKBornZbNPyheiaEJywI1Mik++aTLZK1s4vx05oZs200wQIDAQABo4IB1jCCAdIwDgYDVR0PAQH/BAQD
AgWgMCgGA1UdJQQhMB8GCCsGAQUFBwMCBggqgw4DAwQBAgYJKoMOAwMEAQIBMA8GA1UdIwQIMAaABFtqdBEwHQYDVR0OBBYEFCbExJaY4TDRcEOaBXoJeWqB
KMCFMF4GA1UdIARXMFUwUwYHKoMOAwMCAjBIMCEGCCsGAQUFBwIBFhVodHRwOi8vcGtpLmdvdi5rei9jcHMwIwYIKwYBBQUHAgIwFwwVaHR0cDovL3BraS5n
b3Yua3ovY3BzME4GA1UdHwRHMEUwQ6BBoD+GHWh0dHA6Ly9jcmwucGtpLmdvdi5rei9yc2EuY3Jshh5odHRwOi8vY3JsMS5wa2kuZ292Lmt6L3JzYS5jcmww
UgYDVR0uBEswSTBHoEWgQ4YfaHR0cDovL2NybC5wa2kuZ292Lmt6L2RfcnNhLmNybIYgaHR0cDovL2NybDEucGtpLmdvdi5rei9kX3JzYS5jcmwwYgYIKwYB
BQUHAQEEVjBUMC4GCCsGAQUFBzAChiJodHRwOi8vcGtpLmdvdi5rei9jZXJ0L3BraV9yc2EuY2VyMCIGCCsGAQUFBzABhhZodHRwOi8vb2NzcC5wa2kuZ292
Lmt6MA0GCSqGSIb3DQEBCwUAA4ICAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
"""

PRIVATE_KEY: str = """
MIIEowIBAAKCAQEA1WNO/e5s76m4Tm7CEXqRXGV0AmpN5fGBj2615E5t1KHcDhecwERZ4lWLRktVAOxYKy2iBCM8Nx6w+mInXBndb7BOHFIj8hmOl1hGUOqX
R4cNCfvmeqlUtGhj0SUdvBXlbg0Svm6ic7ax9forH7fx2EnZ+BVRDa5S2rofhDwX3CdF1LKIzyceUW1le3dLVJYH6u+jNY/43Uk3ZuE6AVMCMPZ7JZPi/qhC
lY8+7Q7+kpS69/Xl0AmhbwjO0GpFHri/Uwf8DWcEkPqbMVCsUCqaU8gaC5EPHA/IYEXQmeHpNKBornZbNPyheiaEJywI1Mik++aTLZK1s4vx05oZs200wQID
AQABAoIBABX2mkdNtp22aNd90/DLnlGVyaqD+Y+c23qBaSxeHDTiEg3LRWGOx3eh2Wt7Tn0BVpPfJwlo/QYpXQrwdl+m8+FOksOcesGs+r2+IsKqWrbMgj2Q
VWkzq5nEEt4QhW56DHrW0qKSLZteZxPL04t4ueZKt6ouu4B+fF2yAZNxQf1xR0QYbtwQOCMPnpvh/ipW9DSjBT4wYbd11GqGhFhSsz7C63x0VIoTs+Yv+z/b
6chfHsc6eyt4Vc8RAv9KgpydKVWQiPCD/DdtM2aZrkjdwU4Hke2zT+gala2X6DkHkdHLzl/Lry7f0DX6IuWgMbZk79n3KcL1cjl+87D3PSBDGp8CgYEA6jDc
AsGl45+MJSyBQaPb/JesA9wYfCx9ovK3UV1vAOETZR6buZCEv8uo25GngjpGJ/cvOF8I8NC1SUC68S4IlbOZkDdPWp2MFmjP4thBQ3Tb1UOqCiN8dZ6zGzLM
t4JWS/3q6mkcGvcVh6fiDCDieXi4AD90Ua4dabnkENgPhkMCgYEA6UKBJ3DDY79XxDU1ErDuUgGHEPyJ1w74LWI7+nu8jV9daZTlHE149YAbuyAUjpHYPJMp
wMeIA26IkzsvqeUfIkokExq65vrV2PKWf9w3DpT18qTm+jcLJMCj2b5NdmmIQDBrS/Zmyyx3qws/6s4stkQMrMUzDFZMk8Esa4LWAqsCgYEAuGnHJiiFUAw4
GKHGGwFEXtC0tMlhQo7qVCFa96him8ehNTR4HhTOZBWkn1pAFM18p0X/mh1D9hXzW36sdvTv76pg126mf02mnZLleNUf91WTMom44Yj2HczdbyJ+kFcDS43k
qbghWJ6PBqbN2w0eKddE1XUiTJuWL8Yg8J6jAu8CgYBBnhe/BJWyha0m4ODhNSyVnSBlwuTzvp5KBgxhVlWgX2djwCMDZzfTuAoVBd1CjfyKbcudE4RLktiQ
smGiJXYwqzKivS4+s+lcckGsDkLes0DM1V60nK9h019EbahU2zMc+4HziIk6NnQjhbKhVwZ074exQngtzEkWd40LYW7aqQKBgCdOwCdbePYqL+tO+T6nHsbi
nBxhJnx9X5XWftZY96AKjqPjxLhjvblesX7rf5Dim0BmWguP2byuOooqwDPoolQFT+osa4D9cT4jQJ0Md2aLCGhWrma1R/4FdRocvLiJiR6hPMNuM1h6qzNl
OO2Vt6qaHkOG+zAJrlT42gLolx7T
"""


def print_help_and_exit():
    print(os.path.basename(__file__) +
          ':\n\t★ --type ind|ent (Физическое/Юридическое лицо)'
          '\n\t --iin ИИН [111111111110]'
          '\n\t  --commonname [ИВАНОВ ИВАН]'
          '\n\t  --surname [ИВАНОВ]'
          '\n\t  --country [KZ]'
          '\n\t  --locality [АСТАНА]'
          '\n\t  --state [АСТАНА]'
          '\n\t  --org [ТОО Рога и копыта]'
          '\n\t  --bin БИН [222222222220]'
          '\n\t  --givenname [ИВАНОВИЧ]'
          '\n\t  --email [test@example.com]'
          '\n\t  --keytype [auth] | sign '
          '\n\t  --file (Path to PKCS#12 container)'
          '\n\t  --password')
    sys.exit(1)


def get_cert_params(argv):
    # Сбор параметров запуска

    cert_info = dict(type='', iin='111111111110', commonname='ИВАНОВ ИВАН', surname='ИВАНОВ', country='KZ',
                     locality='АСТАНА', state='АСТАНА', org='ТОО Рога и копыта', bin='222222222220',
                     givenname='ИВАНОВИЧ', email='test@example.com', keytype='auth', file='', password='')

    opts, args = getopt.getopt(argv, "h",
                               ["type=", "iin=", "bin=", "commonname=", "surname=", "country=", "givenname=", "email=",
                                "locality=", "state=", "org=", "bin=", "keytype=", "file=", "password="])
    if not opts:
        opts = [('-h', '')]

    # Check args
    for opt, arg in opts:
        match opt:
            case '-h':
                print_help_and_exit()
            case "--type":
                # Юридическое/Физическое лицо
                if arg in {"ind", "ent"}:
                    cert_info['type'] = arg
                else:
                    print_help_and_exit()
            case "--commonname":
                # CN (Фамилия Имя)
                cert_info['commonname'] = arg
            case "--surname":
                # SN (Фамилия)
                cert_info['surname'] = arg
            case "--iin":
                # serialNumber (ИИН)
                if len(arg) != 12:
                    print("*** Warn: Make sure IIN is the correct length.")
                cert_info['iin'] = arg
            case "--country":
                # C (Country)
                cert_info['country'] = arg
            case "--locality":
                # L (Город)
                cert_info['locality'] = arg
            case "--state":
                # S (Область)
                cert_info['state'] = arg
            case "--org":
                # O (Компания)
                cert_info['org'] = arg
            case "--bin":
                # OU (БИН)
                if len(arg) != 12:
                    print("*** Warn: Make sure BIN is the correct length.")
                cert_info['bin'] = arg
            case "--givenname":
                # G (Отчество)
                cert_info['givenname'] = arg
            case "--email":
                # E (email)
                cert_info['email'] = arg
            case "--file":
                # (file)
                cert_info['file'] = arg
            case "--password":
                # (passwd)
                cert_info['password'] = arg
            case "--keytype":
                # Тип ключа:
                #   auth - для аутентификации
                #   sign - для подписи (только для физ.лица)
                if arg in ("auth", "sign"):
                    cert_info['keytype'] = arg
                else:
                    print("*** Err: Unsupported key type!")
                    sys.exit(1)

    if cert_info['type'] == '':
        print_help_and_exit()

    return cert_info


def get_altered_cert(cert_info):
    # Изменения шаблона сертификата по заданным параметрам

    cert = None
    match cert_info['type']:
        case "ind":
            match cert_info['keytype']:
                case "auth":
                    cert, rest = asn1decoder.decode(base64.b64decode(IND_CERT_AUTH.encode()))
                case "sign":
                    cert, rest = asn1decoder.decode(base64.b64decode(IND_CERT_SIGN.encode()))
        case "ent":
            if cert_info['keytype'] == "sign":
                print("*** Err: Sign key type only supported for individuals")
                sys.exit(1)
            else:
                cert, rest = asn1decoder.decode(base64.b64decode(ENT_CERT_AUTH.encode()))

    '''
    E               = дрес электронный почты
    Serialnumber    = IIN012345678910
    CN              = Фамилия Имя
    SN              = Фамилия
    OU              = BIN012345678910
    O               = Наименование организации
    L               = Город регистрации юридического лица
    S               = Область регистрации юридического лица
    C               = KZ
    G               = Отчество
    '''

    # Changing certificate properties according to run params
    if cert_info['commonname'] != '':
        # CN (Фамилия Имя)
        cert['field-0']['field-5'][0][0]['field-1'] = cert_info['commonname']
    if cert_info['surname'] != '':
        # SN (Фамилия)
        cert['field-0']['field-5'][1][0]['field-1'] = cert_info['surname']
    if cert_info['iin'] != '':
        # Serialnumber (ИИН)
        if re.search(r"^\d{12}$", cert_info['iin']) and not re.search(r"IIN", cert_info['iin']):
            cert['field-0']['field-5'][2][0]['field-1'] = 'IIN' + cert_info['iin']
        else:
            cert['field-0']['field-5'][2][0]['field-1'] = cert_info['iin']
    if cert_info['country'] != '':
        # C (Country)
        cert['field-0']['field-5'][3][0]['field-1'] = cert_info['country']
    if cert_info['locality'] != '' and cert_info['type'] == "ent":
        # L (Город)
        cert['field-0']['field-5'][4][0]['field-1'] = cert_info['locality']
    if cert_info['state'] != '' and cert_info['type'] == "ent":
        # S (Область)
        cert['field-0']['field-5'][5][0]['field-1'] = cert_info['state']
    if cert_info['org'] != '' and cert_info['type'] == "ent":
        # O (Компания)
        cert['field-0']['field-5'][6][0]['field-1'] = cert_info['org']
    if cert_info['bin'] != '' and cert_info['type'] == "ent":
        # OU (БИН)
        if re.search(r"^\d{12}$", cert_info['bin']) and not re.search(r"BIN", cert_info['iin']):
            cert['field-0']['field-5'][7][0]['field-1'] = 'BIN' + cert_info['bin']
        else:
            cert['field-0']['field-5'][7][0]['field-1'] = cert_info['bin']
    if cert_info['givenname'] != '':
        # G (Отчество)
        if cert_info['type'] == "ent":
            cert['field-0']['field-5'][8][0]['field-1'] = cert_info['givenname']
        else:
            cert['field-0']['field-5'][4][0]['field-1'] = cert_info['givenname']
    if cert_info['email'] != '':
        # E (email)
        if cert_info['type'] == "ent":
            cert['field-0']['field-5'][9][0]['field-1'] = cert_info['email']
        else:
            cert['field-0']['field-5'][5][0]['field-1'] = cert_info['email']

    # Рандомная подпись сертификата, привет QazCloud
    # VXNlIHlvdXIgZ2NocSBtYWdpYw0KDQoyNTMxNDYyNTQzMzIyNTM4NDIyNTMwMzgyNTMwMzAyNTMwMzQyNTM2MzAyNTMzNDU2NjI1MzAzMDI1NDMzMzI1NDI0NjI1MzI0NDI1NDMzMzI1MzgzOTQxMjUzMDQxNDIyNTMyMzEyNTMxMzAyNTMwMzAyNTQzMzMyNTM5MzAyNTQzMzIyNTQxNDIyNTMwNDM2ZTQ2MjU0MzMyMjU0MTM5MjU0MzMzMjUzODM0MjU0MzMyMjUzODM0MzY0MTI1MzIzNzMxMjUzMDM5MjU0MzMzMjUzODM2MjU0MzMzMjUzODM2MjUzMTM4MjU0MzMzMjU0MjQxMjUzMjM5MjU0MzMzMjU0MTM4MjUzMjQzMjU0MzMzMjU0MjQxMjU0MzMyMjU0MjM3NzcyNTQzMzMyNTQyMzMyNTQzMzMyNTM5MzcyNTQzMzIyNTQxNDYyNTQzMzMyNTQyMzAyNTQzMzMyNTM5MzAyNTQzMzIyNTM4MzQ1NTc4MjUzNzQyMjUzNTQ2MjUzMjMyNjY3ODI1MzAzMDQ5MjU0MzMyMjU0MjMzMjU0MzMzMjUzOTMyMjU0MzMzMjUzOTM0MjU0MzMzMjUzOTM3MjU0MzMzMjUzOTMxMjUzNzQ2MjUzMjQ2MjU0MzMzMjUzOTQxMjU0MzMyMjUzOTM1MjU0MzMyMjU0MTM3MjUzMjM1MjUzNzQzMjU0MzMzMjU0MjQ1NDMyNTM0MzAzODI1NDMzMzI1MzgzMTI1NDMzMzI1NDEzNDMyNTgyNTQzMzIyNTQxMzcyNTQzMzMyNTM5MzcyNTQzMzMyNTQyNDUyNTQzMzMyNTQxMzU3NjI1NDMzMzI1NDEzODI1NDMzMzI1NDE0NDI1MzE0MTI1NDMzMzI1Mzk0NDI1MzEzOTI1MzA0MzI1NDMzMzI1MzgzOTI1NDMzMzI1MzgzNzM4MjU0MzMyMjUzOTM3MjU0MzMzMjU0MTMyMjUzMzQ0MjUzMjQ2MjUzMDM1MjU0MzMyMjU0MjQ0MzIyNTMwMzY1NDI1MzAzMDI1MzAzMDI1MzAzMA==

    # Adjusting the certificate date in the range of 180 days
    cert['field-0']['field-4'][0] = (datetime.now() - timedelta(days=180)).strftime("%y%m%d%H%M%S") + 'Z'
    cert['field-0']['field-4'][1] = (datetime.now() + timedelta(days=180)).strftime("%y%m%d%H%M%S") + 'Z'

    # Serialize back to ASN.1 and return in base64 encoded certificate
    return base64.b64encode(asn1encoder.encode(cert)).decode('ascii')


def main(argv):
    global altered_cert
    global cert_info
    cert_info = get_cert_params(argv)
    altered_cert = get_altered_cert(cert_info)

    if cert_info['file'] == None or cert_info['password'] == None:
        print("*** Err: No file name or password provided")
        sys.exit(1)

    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(altered_cert))
        key = serialization.load_der_private_key(base64.b64decode(PRIVATE_KEY), None)
        p12 = pkcs12.serialize_key_and_certificates(
            b"26C4C49698E130D170439A057A09796A8128C085", key, cert, None, BestAvailableEncryption(
                cert_info['password'].encode('utf-8'))
        )
        with open(cert_info['file'], "wb") as file:
            file.write(p12)
            file.close()

        print("OK")

    except OSError as err:
        print("*** Err: " + err.strerror)
        sys.exit(1)
    except ValueError as err:
        print("*** Err: " + err.__str__())
        sys.exit(1)



if __name__ == "__main__":
    main(sys.argv[1:])
