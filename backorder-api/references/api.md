# API, ответы и выгрузка

## Канонические запросы

```text
https://backorder.ru/billmgr?func=backorder_list&out=backorder&filter=off&filter_params=expired&limit=10&offset=0&content_only=off&order_by=hotness&sort_order=desc
https://backorder.ru/json/?filter_params=expired&include=interesting&order_by=hotness&sort_order=desc
https://backorder.ru/csv/?filter_params=expired&include=interesting&order_by=hotness&sort_order=desc
```

Все фильтры перечислены в [filters.md](filters.md). Основной API публичного поиска не требует авторизации. Авторизация нужна для персональных методов и `my_orders`; без предоставленного пользователем доступа не обещай персональные результаты.

Параметры после `#` в адресе сайта — состояние frontend. Для HTTP-запроса они должны стать query после `?`. Списки hash разделены `|`, query API/экспорта — запятыми. Пары шаблонов `contains` и строка `org` — отдельный синтаксис: не заменяй в них все `|` автоматически.

## Основной JSON

Схема ответа:

```json
{"aggregation":{"total":2,"registrars":{"REGRU":{"REGRU-RU":2}},"zones":{"ru":2}},"records":[{"domain":"moonbot.ru","donors":1,"age":2,"price":{"current":0,"next":190}}]}
```

Это сокращённая иллюстрация реального ответа, а не полный набор обязательных полей. `records` содержит домены, `aggregation.total` — число совпадений всей выборки. Счётчики по режимам и признакам не обязаны быть равны `total`: часть агрегаций отражает более широкий контекст поиска.

Основные поля: `domain`, `registrar`, `hotness`, `x_value`, `yandex_tic`, `donors`, `visitors`, `hits`, `org`, `person`, `age`, `age_first_reg`, `age_prev_reg`, `creation_date`, `first_creation_date`, `previous_creation_date`, `paid_till`, `free_date`, `delete_date`, `real_delete_date`, `drop_close_time`, флаги `is_free`, `is_interesting`, `is_intercepted`, `is_judicial`, `is_blocked`, `is_rkn_blocked`, `is_pending_delete`.

`price` — объект `current`, `next`, `min`, `max`, `avg`; не превращай его в одно число без определения нужной цены. `org` или `person` могут отсутствовать. Метрики могут быть `null`. `real_delete_date=1970-01-01` наблюдалась как заглушка; не используй её как фактическую дату. Поля первичной/прошлой регистрации есть в фактическом ответе, хотя часть из них отсутствует в опубликованной схеме `domain`.

Для пагинации основного API увеличивай `offset` на фактический размер страницы, заверши при пустой странице или достижении `total`. Не делай вывод о полноте только по одной странице. При `content_only=on` не рассчитывай на агрегацию; сохрани `total` первого запроса или заверши на пустой странице. Поскольку данные меняются, при длительной выгрузке выбирай определённую сортировку (например, `domain`), удаляй дубли и сообщай время сбора; транзакционный снимок API не обещан.

Значение `limit=0` разрешено OpenAPI, но его фактическое назначение отдельно не проверялось. Для предсказуемого чтения используй положительный размер страницы.

## Экспорт JSON/CSV

`/json/` возвращает **массив**, без `records` и агрегаций. Проверенная схема одной строки:

```json
{"domainname":"moonbot.ru","hotness":10,"price":0,"x_value":0,"yandex_tic":0,"links":1,"visitors":"","registrar":"REGRU-RU","old":2,"delete_date":"2026-11-19","rkn":false,"judicial":false,"block":false}
```

| Экспорт | Основной API | Замечание |
|---|---|---|
| `domainname` | `domain` | Имя домена |
| `links` | `donors` | Сопоставление на контрольных данных |
| `old` | `age` | Текущий возраст в проверенном экспорте; переключения исторической регистрации не проверены на ответах выгрузки |
| `price` | `price.current` | На контрольных строках совпало с `current`; не с сортировочным `price_next` |
| `rkn` | `is_rkn_blocked` | Флаг |
| `judicial` | `is_judicial` | Флаг |
| `block` | `is_blocked` | Флаг |

CSV: UTF-8, разделитель **`;`**, значения и названия колонок заключены в двойные кавычки, строки CRLF. Булевы значения — строки `true`/`false`; отсутствующий трафик был пустой строкой. Используй `csv.DictReader(..., delimiter=';')`, не ручное разбиение по запятой.

Ограничение 30 000 указано в старой официальной документации; граничный запрос на 30 001 строку не выполнялся. Игнорирование `limit=1` текущими обоими экспортами проверено на двух доменах; отсутствие надёжной пагинации учитывать обязательно. `page/items` игнорируются по документации. Не называй экспорт полным при неизвестном размере исходной выборки или ровно 30 000 полученных строках.

## Дополнительные публичные методы

Везде основа: `/billmgr?func=МЕТОД&out=backorder`. Ниже — имена из OpenAPI; кроме контрольных запросов в журнале эти методы не проверялись вызовом. Перед нетривиальным использованием сверяй актуальную схему.

| Метод | Параметры | Задача |
|---|---|---|
| `backorder_list.mget` | `domain=sib.ru,moonbot.ru` | Точное получение списка доменов; также допускаются пробелы/`|` как разделители |
| `backorder_list.calendar` | `real_free_date=on|off` | Календарь удаления |
| `backorder_list.next_drop` | — | Следующая дата удаления |
| `backorder_list.history` | `elid=домен` | История WHOIS |
| `backorder_list.whois` | **`domain=домен`** | WHOIS; имя параметра отличается от `elid` |
| `backorder_list.info` | `elid=домен` | Данные домена |
| `backorder_list.traffic` | `elid=домен` | История посещаемости |
| `backorder_list.donors` | `elid=домен` | История доноров/ссылок |
| `backorder_list.x_value` | `elid=домен` | История ИКС |
| `backorder_list.tic` | `elid=домен` | История тИЦ |
| `backorder_list.rkn` | `elid=домен` | История РКН |
| `backorder_list.price` | `elid=домен` | График цены |
| `backorder_list.icon` | `elid=домен` | Фавикон |
| `backorder.top_deleting` | `limit`, `freedate_start`, `freedate_end`, `zones` | Топ удаляющихся |
| `backorder.top_deleted` | обязательные `start`, `end`; `limit`, `zones`, `backorder` | Топ удалённых; документированный максимум `limit=10000` |
| `backorder.status_groups` | — | Группы статусов |
| `backorder.status_map` | `lang=ru` | Локализованные статусы |

## Ошибки и доступ

Проверяй статус HTTP, JSON и наличие `error`. Пример ошибки ограничения: `{"error":{"type":"access_blocked","msg":"...","request_id":"..."}}`. Во время проверки получены 429 с этим объектом, а не домены. Не сохраняй такой ответ как успешный список. При диагностике можно сообщить `request_id`, не публикуя session/auth/cookie и другие секреты.

При обычном ограничении частоты уважай `Retry-After`, выполняй запросы последовательно. При CAPTCHA/`access_blocked` остановись; не меняй IP, не имитируй обход и не бесконечно повторяй запрос. Страница Swagger может открываться в Chrome, даже когда внешняя загрузка страницы возвращает CAPTCHA.

Утилита `backorder_api.py` делает только публичные запросы списка, mget и экспорта. Не реализует персональные методы или вход. Для авторизованной работы используй явно предоставленный доступ и актуальную схему; секреты не сохраняй в документации, журнале и URL, показанных пользователю.
