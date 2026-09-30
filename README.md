# Curl Impersonate Proxy для Fiddler Classic

Расширение для Fiddler Classic, которое позволяет отправлять перехваченные HTTP- и HTTPS-запросы через `curl-impersonate`.

При этом сохраняется привычная работа с Fiddler: инспекторы, правила, расшифровка HTTPS и список сессий. Исходящие запросы отправляются через `curl-impersonate` и могут использовать браузерные TLS-отпечатки, HTTP/2 и HTTP/3.

## Как это работает

```text
Браузер  <-- HTTP/1.1 -->  Fiddler Classic  -->  Curl Impersonate Proxy  <-- HTTP/2 или HTTP/3 -->  Сайт
```

Встроенная сборка curl основана на [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate).

## Возможности

- Поддержка HTTP/2 и HTTP/3.
- Поддержка профилей браузеров curl-impersonate.
- Отображение фактически используемой версии HTTP в завершённых сессиях Fiddler.

## Использование

Откройте меню:

```text
Rules > Curl Impersonate Proxy
```

## Установка

Скопируйте содержимое архива `RELEASE` в:

```text
%USERPROFILE%\Documents\Fiddler2\Scripts
```


## Компиляция

1. Закройте Fiddler Classic.

2. Соберите нативный прокси:

```bat
build.bat
```

3. Соберите расширение:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  '.\FiddlerExtension\FiddlerBrowserProxyExtension.csproj' `
  /t:Rebuild /p:Configuration=Release
```

После сборки расширение и прокси автоматически устанавливаются в:

```text
%USERPROFILE%\Documents\Fiddler2\Scripts
```

