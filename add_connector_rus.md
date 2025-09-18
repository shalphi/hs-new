# Руководство по интеграции коннектора

## Оглавление

1. [Введение](#введение)  
2. [Предварительные требования](#предварительные-требования)  
3. [Настройка и конфигурация среды разработки](#настройка-и-конфигурация-среды-разработки)  
4. [Создание коннектора](#создание-коннектора)  
5. [Тестирование соединения](#тестирование-соединения)  
6. [Структура папок после выполнения скрипта](#структура-папок-после-выполнения-скрипта)  
7. [Общие типы потоков платежей](#общие-типы-потоков-платежей)  
8. [Интеграция нового коннектора](#интеграция-нового-коннектора)  
9. [Обзор кода](#обзор-кода)  
10. [Обработка ошибок в коннекторах Hyperswitch](#обработка-ошибок-в-коннекторах-hyperswitch)  
11. [Реализация интерфейса коннектора](#реализация-интерфейса-коннектора)  
12. [ConnectorCommon: Базовый трейт](#connectorcommon-базовый-трейт)  
13. [ConnectorIntegration – Оркестратор потока платежей](#connectorintegration--оркестратор-потока-платежей)  
14. [Разбор по методам](#разбор-по-методам)  
15. [Обзор трейтов коннектора](#обзор-трейтов-коннектора)  
16. [Производные трейты](#производные-трейты)  
17. [Утилитарные функции коннектора](#утилитарные-функции-коннектора)  
18. [Конфигурация коннектора для интеграции с Control Center](#конфигурация-коннектора-для-интеграции-с-control-center)  
19. [Интеграция фронтенда Control Center](#интеграция-фронтенда-control-center)  
20. [Тестирование интеграции коннектора](#тестирование-интеграции-коннектора)  

## Введение

Это руководство содержит инструкции по интеграции нового коннектора с Router, от настройки среды до реализации API-взаимодействий. В этом документе вы узнаете, как:

* Создать шаблон нового коннектора
* Определить типы запросов/ответов Rust напрямую из JSON-схемы вашего PSP
* Реализовать трансформеры и трейт `ConnectorIntegration` как для стандартной аутентификации, так и для потоков с токенизацией
* Обеспечить лучшие практики PII (обертки Secret, типы common_utils::pii) и надежную обработку ошибок
* Обновить Control-Center (ConnectorTypes.res, ConnectorUtils.res, иконки)
* Валидировать ваш коннектор с помощью end-to-end тестов

К концу вы научитесь создавать полнофункциональный, готовый к продакшену коннектор — от чистого листа до живого в Control-Center.

## Предварительные требования

* Перед началом убедитесь, что вы завершили первоначальную настройку в нашем [Руководстве для участников Hyperswitch](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/docs/CONTRIBUTING.md?plain=1#L1), которое покрывает клонирование, установку инструментов и доступ.
* Вы также должны понимать [коннекторы и способы оплаты](https://hyperswitch.io/pm-list).
* Знакомство с API коннектора, который вы интегрируете
* Локально настроенный и работающий репозиторий Router
* API-учетные данные для тестирования (зарегистрируйтесь для получения sandbox/UAT учетных данных на сайте коннектора).
* Нужна помощь? Присоединяйтесь к [Hyperswitch Slack Channel](https://inviter.co/hyperswitch-slack). У нас также есть еженедельные рабочие часы каждый четверг в 8:00 AM PT (11:00 AM ET, 4:00 PM BST, 5:00 PM CEST, и 8:30 PM IST). Ссылка на рабочие часы публикуется в канале **#general**.

## Настройка и конфигурация среды разработки

Это руководство проведет вас через настройку и конфигурацию вашей среды.

### Клонирование монорепозитория Hyperswitch

```bash
git clone git@github.com:juspay/hyperswitch.git
cd hyperswitch
```

### Настройка среды Rust и зависимостей

Перед запуском Hyperswitch локально убедитесь, что ваша среда Rust и системные зависимости правильно настроены.

**Следуйте руководству**:

[Настройка Rust и установка необходимых зависимостей на основе вашей ОС](https://github.com/juspay/hyperswitch/blob/main/docs/try_local_system.md#set-up-a-rust-environment-and-other-dependencies)

**Быстрые ссылки по ОС**:
* [Системы на основе Ubuntu](https://github.com/juspay/hyperswitch/blob/main/docs/try_local_system.md#set-up-dependencies-on-ubuntu-based-systems)
* [Windows (WSL2)](https://github.com/juspay/hyperswitch/blob/main/docs/try_local_system.md#set-up-dependencies-on-windows-ubuntu-on-wsl2)
* [Windows (нативный)](https://github.com/juspay/hyperswitch/blob/main/docs/try_local_system.md#set-up-dependencies-on-windows)
* [macOS](https://github.com/juspay/hyperswitch/blob/main/docs/try_local_system.md#set-up-dependencies-on-macos)

**Все ОС**:
* [Настройка базы данных](https://github.com/juspay/hyperswitch/blob/main/docs/try_local_system.md#set-up-the-database)

* Настройка ночного инструментария Rust для форматирования кода:

```bash
rustup toolchain install nightly
```

* Установка [Protobuf](https://protobuf.dev/installation/)

Установка cargo-generate для создания шаблонов проектов:

```bash
cargo install cargo-generate
```

Если вы завершили настройку, у вас должно быть:

* ✅ Rust & Cargo
* ✅ `cargo-generate`
* ✅ PostgreSQL (с созданными пользователем и базой данных)
* ✅ Redis
* ✅ `diesel_cli`
* ✅ Команда `just`
* ✅ Применены миграции базы данных
* ✅ Настроен ночной инструментарий Rust
* ✅ Установлен Protobuf

Скомпилируйте и запустите приложение с помощью cargo:

```bash
cargo run
```

## Создание коннектора

Из корня проекта сгенерируйте новый коннектор, выполнив следующую команду. Используйте имя из одного слова для вашего `ConnectorName`:

```bash
sh scripts/add_connector.sh <ConnectorName> <ConnectorBaseUrl>
```

При выполнении скрипта вы должны увидеть, что некоторые файлы были созданы

```bash
# Готово! Новый проект создан /абсолютный/путь/hyperswitch/crates/hyperswitch_connectors/src/connectors/connectorname
```

> ⚠️ **Предупреждение**  
> Не пугайтесь, если увидите сбои тестов на этом этапе.  
> Тесты еще не реализованы для вашего нового коннектора, поэтому сбои ожидаемы.  
> Вы можете безопасно игнорировать вывод типа:
>
> ```bash
> test result: FAILED. 0 passed; 20 failed; 0 ignored; 0 measured; 1759 filtered out; finished in 0.10s
> ```
> Вы также можете игнорировать ошибки GRPC.

## Тестирование соединения

После успешного создания коннектора с помощью скрипта `add_connector.sh` вы можете проверить интеграцию, запустив службу Hyperswitch Router:

```bash
cargo r
```

Это запускает приложение router локально на `порту 8080`, предоставляя доступ к полному API Hyperswitch. Теперь вы можете тестировать реализацию вашего коннектора, делая HTTP-запросы к конечным точкам платежей для операций типа:

- Авторизация и захват платежей
- Синхронизация платежей
- Обработка возвратов
- Обработка вебхуков

После реализации логики коннектора эта среда позволяет убедиться, что он ведет себя правильно в потоке оркестрации Hyperswitch — перед переходом к staging или продакшену.

### Проверка состояния сервера

После запуска службы Hyperswitch Router вы можете проверить ее работоспособность, проверив конечную точку health в отдельном окне терминала:

```bash
curl --head --request GET 'http://localhost:8080/health'
```

> **Пункт действий**  
> После создания коннектора выполните проверку health, чтобы убедиться, что все работает гладко.

### Структура папок после выполнения скрипта

При выполнении скрипта создается специфическая структура папок для вашего нового коннектора. Вот что генерируется:

**Основные файлы коннектора**

Скрипт создает основную структуру коннектора в crate hyperswitch_connectors:

```
crates/hyperswitch_connectors/src/connectors/  
├── <connector_name>/  
│   └── transformers.rs  
└── <connector_name>.rs
```

#### Тестовые файлы

Скрипт также генерирует тестовые файлы в crate router:

```
crates/router/tests/connectors/  
└── <connector_name>.rs 
```

**Что содержит каждый файл**

- `<connector_name>.rs`: Основной файл реализации коннектора, где вы реализуете трейты коннектора
- `transformers.rs`: Содержит структуры данных и логику преобразования между внутренним форматом Hyperswitch и форматом API вашего платежного процессора
- **Тестовый файл**: [Содержит шаблонные тестовые случаи для вашего коннектора](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/connector-template/test.rs#L1-L36).

## Общие типы потоков платежей

При создании коннектора вы столкнетесь с различными паттернами потоков платежей.  
Этот раздел дает вам:

- Быструю справочную таблицу для всех потоков  
- Примеры двух наиболее распространенных паттернов: **Токенизация‑первая** и **Прямая авторизация**

> Для полной информации см. [документацию по потокам платежей коннектора](https://docs.hyperswitch.io/learn-more/hyperswitch-architecture/connector-payment-flows) или спросите нас в Slack.

---

### 1. Сводная таблица потоков

| Название потока           | Описание                                      | Реализация в Hyperswitch |
|---------------------------|-----------------------------------------------|--------------------------|
| **Access Token**          | Получение OAuth access token                 | [crates/hyperswitch_interfaces/src/types.rs#L7](https://github.com/juspay/hyperswitch/blob/06dc66c62e33c1c56c42aab18a7959e1648d6fae/crates/hyperswitch_interfaces/src/types.rs#L7) |
| **Tokenization**          | Обмен учетных данных на платежный токен       | [crates/hyperswitch_interfaces/src/types.rs#L148](https://github.com/juspay/hyperswitch/blob/06dc66c62e33c1c56c42aab18a7959e1648d6fae/crates/hyperswitch_interfaces/src/types.rs#L148) |
| **Customer Creation**     | Создание или обновление записей клиентов      | [crates/router/src/types.rs#L40](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/router/src/types.rs#L40) |
| **Pre‑Processing**        | Валидация или обогащение перед auth           | [crates/router/src/types.rs#L41](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/router/src/types.rs#L41) |
| **Authorization**         | Авторизация и немедленный захват платежа      | [crates/hyperswitch_interfaces/src/types.rs#L12](https://github.com/juspay/hyperswitch/blob/06dc66c62e33c1c56c42aab18a7959e1648d6fae/crates/hyperswitch_interfaces/src/types.rs#L12) |
| **Authorization‑Only**    | Авторизация платежа для последующего захвата  | [crates/router/src/types.rs#L39](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/router/src/types.rs#L39) |
| **Capture**               | Захват ранее авторизованного платежа          | [crates/router/src/types.rs#L39](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/router/src/types.rs#L39) |
| **Refund**                | Выдача возврата                               | [crates/router/src/types.rs#L44](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/router/src/types.rs#L44) |
| **Webhook Handling**      | Обработка асинхронных событий от PSP          | [crates/router/src/types.rs#L45](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/router/src/types.rs#L45) |

---

### Определения типов потоков

Каждый тип потока соответствует специфическим структурам данных запроса/ответа и паттернам интеграции коннектора. Все потоки следуют стандартизированному паттерну с ассоциированными:

- **Типы данных запроса** (например, `PaymentsAuthorizeData`)
- **Типы данных ответа** (например, `PaymentsResponseData`)
- **Обертки данных Router** для коммуникации с коннектором

### 2. Паттерн: Токенизация‑первая

Некоторые PSP требуют, чтобы данные платежа были токенизированы перед авторизацией.  
Это **двухэтапный процесс**:  

1. **Токенизация** – например, реализация Billwerk:  
   - [Токенизация](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/hyperswitch_connectors/src/connectors/billwerk.rs#L178-L271)  
   - [Авторизация](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/hyperswitch_connectors/src/connectors/billwerk.rs#L273-L366)  

2. **Авторизация** – Использует возвращенный токен вместо сырых данных платежа.  

> Большинство PSP не требуют этого; см. следующий раздел для прямой авторизации.

---

### 3. Паттерн: Прямая авторизация

Многие коннекторы пропускают токенизацию и отправляют данные платежа напрямую в запросе авторизации.  

- **Authorize.net** – [код](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/hyperswitch_connectors/src/connectors/authorizedotnet.rs#L401-L497)  
  Строит `CreateTransactionRequest` напрямую из данных платежа в `get_request_body()`.  

- **Helcim** – [код](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/hyperswitch_connectors/src/connectors/helcim.rs#L295-L385)  
  Выбирает конечную точку purchase (авто-захват) или preauth в `get_url()` и обрабатывает данные платежа напрямую.  

- **Deutsche Bank** – [код](https://github.com/juspay/hyperswitch/blob/2309c5311cb9a01ef371f3a3ef7c62c88a043696/crates/hyperswitch_connectors/src/connectors/deutschebank.rs#L330-L461)  
  Выбирает поток на основе 3DS и типа платежа (карта или прямое дебетование).  

**Ключевые отличия от токенизации-первая:**
- Один API-вызов – Нет отдельного шага токена  
- Нет хранения токенов – Не требуется управление токенами  
- Немедленная обработка – `get_request_body()` обрабатывает данные платежа напрямую  

Все реализуют один и тот же паттерн `ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData>`.

## Интеграция нового коннектора

Интеграция коннектора в основном является задачей интеграции API. Вы определите типы запросов и ответов и реализуете необходимые трейты.

Этот раздел покрывает платежи картами через Billwerk. Просмотрите справочник API и тестируйте API перед началом. Вы можете использовать эти примеры для коннектора по вашему выбору.

### 1. Создание запроса и ответа платежа из JSON-схемы

Для генерации типов Rust из OpenAPI или JSON-схемы вашего коннектора вам нужно установить [OpenAPI Generator](https://openapi-generator.tech/).

#### Пример (macOS с использованием Homebrew):

```bash
brew install openapi-generator
```

> 💡 **Примечание:**  
> На **Linux** вы можете установить OpenAPI Generator используя `apt`, `snap`, или скачав JAR с [официального сайта](https://openapi-generator.tech/docs/installation).  
> На **Windows** используйте [Scoop](https://scoop.sh/) или вручную скачайте JAR-файл.

### 2. Скачивание спецификации OpenAPI от вашего коннектора

Сначала получите спецификацию OpenAPI из документации разработчика вашего платежного процессора:

```bash
curl -o <ConnectorName>-openapi.json <schema-url>
```

**Конкретный пример для Billwerk:**

```bash
curl -o billwerk-openapi.json https://sandbox.billwerk.com/swagger/v1/swagger.json
```

### 3. Конфигурация переменных среды

```bash
export CONNECTOR_NAME="ConnectorName"
export SCHEMA_PATH="/абсолютный/путь/к/вашему/connector-openapi.json"
```

## Краткий обзор оставшихся разделов

Полное руководство содержит также следующие важные разделы:

### Обзор кода
- Преобразование данных Hyperswitch в формат API коннектора
- Обработка сопоставления ответов
- Сопоставление статусов платежей
- Обработка ошибок

### Реализация интерфейса коннектора
- Трейт `ConnectorCommon` - базовая функциональность
- Трейт `ConnectorIntegration` - оркестратор потока платежей
- Методы `get_url()`, `get_headers()`, `get_request_body()`, `handle_response()`

### Конфигурация и тестирование
- Настройка WebAssembly компонентов для Control Center
- Интеграция с фронтендом Control Center
- Настройка аутентификации и тестирование

### Практические примеры
- Примеры кода на основе коннектора Billwerk
- Утилитарные функции для работы с данными карт и клиентов
- Обработка различных типов ошибок

## Заключение

Это руководство предоставляет полную инструкцию по созданию коннектора для Hyperswitch. Для получения детальной информации по каждому разделу обратитесь к оригинальному файлу `add_connector.md`.

Основные шаги:
1. Настройка среды разработки
2. Создание коннектора с помощью скрипта
3. Реализация трансформеров и трейтов
4. Настройка конфигурации
5. Тестирование интеграции

Для получения помощи присоединяйтесь к [Hyperswitch Slack Channel](https://inviter.co/hyperswitch-slack).
