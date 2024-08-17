Данный репозиторий содержит две утилиты для тестирования ИС, использующих ЭЦП для аутентификации и подписи данных. Поддерживается только алгоритм подписи RSA.


### FCALayer
Fake Certification Authority Layer

Утилита для аутентификации по ЭЦП в уязвимых системах, не проверяющих подлинность сертификата НУЦ РК. 
Для использования необходимо  закрыть NCALayer.

Не является полноценной заменой NCALayer, и реализует только методы использовавшиеся в теститируемых  системах.

**Модули и методы**

 - kz.gov.pki.knca.basics:
	 - sign (xml/cms)
- kz.gov.pki.knca.commonUtils:
	- createCMSSignatureFromBase64 (без TSA)
    - createCAdESFromBase64 (без TSA)
	- getKeyInfo	
	- signXml
	- signXmls
    - getActiveTokens (PKCS12)
- kz.gov.pki.knca.applet.Applet:
	- signXml
	- signPlainData
	- getSubjectDN
    - getNotAfter
    - getNotBefore
    - browseKeyStore (заглушка)
    - loadSlotList (заглушка)
    - verifyXml (заглушка)
    - getKeys
- kz.gov.pki.ncalayerservices.accessory:
  - getBundles (заглушка)

**Функциональные возможности**
- Имитация работы NCALayer по протоколу Websocket;
- Подпись данных в различтых форматах - XMLDsig/CMS/CAdES
- Создание невалидного сертификата для физ и юр. лиц с нужными свойствами при запуске по шаблону:
  - Сертификат физического лица для аутентификации (AUTH_RSA256_*.p12)
  - Сертификат физического лица для подписи (RSA256_*.p12)
  - Сертификат юридического лица для аутентификации (AUTH_RSA256_*.p12)
- Исползование валидного сертификата и ключа из файла PKCS#12 (.p12)
- Установка задержки отправки подписи для проверки истечения токена аутентифкации в ИС
- Намеренная поломка цифровой подписи данных проверки ее валидации на ИС

**Использование**

1. Установка зависимостей Python 3.10+: `pip install -r requirements.txt`  
2. Корневой сертификат `FCALayer-CA.crt` должен быть установлен как доверенный в браузер.

Параметры запуска:  
```
FCALayer.py:                                                                        
       ★ --type ind|ent|file (Физическое/Юридическое лицо/PKCS#12 file)
          --iin ИИН [111111111110]
          --commonname [ИВАНОВ ИВАН]
          --surname [ИВАНОВ]
          --country [KZ]
          --locality [АСТАНА]
          --state [АСТАНА]
          --org [ТОО Рога и копыта]
          --bin БИН [222222222220]
          --givenname [ИВАНОВИЧ]
          --email [test@example.com]
          --dontsend (Don\'t send signature)
          --keytype [auth] | sign
          --delay [0] Delay for signature send in seconds
          --file (path to file)
          --password (PKCS#12 container password)
          --break-signature (Send broken signature) 
```

### make-p12

Утилита для создания невалидных сертификатов НУЦ РК по различным шаблонам:
- Сертификат физического лица для аутентификации (AUTH_RSA256_*.p12)
- Сертификат физического лица для подписи (RSA256_*.p12)
- Сертификат юридического лица для аутентификации (AUTH_RSA256_*.p12)

**Использование**

1. Установка зависимостей Python 3.10+: `pip install -r requirements.txt` 

Параметры запуска:  
```
make-p12.py:                                                                        
       ★ --type ind|ent (Физическое/Юридическое лицо)
          --iin ИИН [111111111110]
          --commonname [ИВАНОВ ИВАН]
          --surname [ИВАНОВ]
          --country [KZ]
          --locality [АСТАНА]
          --state [АСТАНА]
          --org [ТОО Рога и копыта]
          --bin БИН [222222222220]
          --givenname [ИВАНОВИЧ]
          --email [test@example.com]
          --keytype [auth] | sign
          --file (Path to PKCS#12 container)
          --password

```

**P.S.**

Программное обеспечение написано только для образовательных целей, используйте только с разрешения владельца.   
The software is written for educational purposes only, use only if you have permission of the owner.