# FCALayer
Fake Certification Authority Layer

Утилита для аутентификации по ЭЦП в уязвимых системах, не проверяющих подлинность сертификата НУЦ РК.  
Для использования необхродимо закрыть NCALayer.

Установка зависимостей Python 3.10+: `pip install requests future pyasn1 pycryptodome websockets`  
Корневой сертификат `FCALayer-CA.crt` должен быть установлен как доверенный в браузер.

Параметры запуска:  
```
FCALayer.py:                                                                        
        --type ind|ent (Физическое/Юридическое лицо)
        [ --iin ИИН [111111111110]
          --commonname [ИВАНОВ ИВАН]
          --surname [ИВАНОВ]
          --country [KZ]
          --locality [АСТАНА]
          --state [АСТАНА]
          --org [ТОО Рога и копыта]
          --bin БИН [222222222220]
          --givenname [ИВАНОВИЧ]
          --email [test@example.com]]
          --dontsend (Don't send signature) ]
```


Программное обеспечение написано только для образовательных целей. Используйте только с разрешения владельца.  
The software is written for educational purposes only. Use only if you have permission of the owner.

Copyright (c) 2023 Konstantin Burov. All rights reserved.  
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.
