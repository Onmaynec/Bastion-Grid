# Модель угроз локального стенда

Защищаемые данные: credentials, tenant objects, события, версии кейсов, согласования, evidence и журнал. Доверенные компоненты: локальный администратор, процесс приложения и файловая система. Компрометация хоста находится вне гарантий этой версии.

| Угроза | Реализованная мера | Проверка | Остаток |
|---|---|---|---|
| Подмена tenant в JSON | Закрытая схема и scope из identity | test_tenant_from_server_only | Нет PostgreSQL RLS |
| IDOR по известному чужому ID | Tenant в SQL и одинаковый 404 | test_cross_tenant_transition | Добавлен ABAC по связанным объектам; полного property-based suite RFP нет |
| Кража устаревшего сеанса | TTL и проверка revocation в каждом запросе | test_revocation_invalidates_cookie | Ротация lab key и отзыв сеансов есть; OIDC refresh rotation нет |
| CSRF и DNS rebinding | CSRF, SameSite, Origin, Host allowlist | test_csrf, test_cross_origin_and_host | Только HTTP loopback |
| Повтор сообщения | Unique scoped key + content digest | test_concurrent_dedup | Нет broker replay/partition fault tests |
| Потеря части batch | Одна SQL-транзакция | test_invalid_batch_is_atomic | Нет испытаний power loss |
| Перезапись изменения кейса | If-Match | test_state_machine_version_and_reason | Нет распределённых писателей |
| Самосогласование | Сравнение субъектов, независимые 2 голоса | test_self_approval_even_if_role_elevated | Нет MFA assurance |
| Выполнение произвольной команды | Нет dispatcher, allowlist только заявок | test_no_arbitrary_command | Реального response нет |
| Подмена evidence | Body hash в acquisition audit + content hash | test_tampered_payload_and_metadata | Нет подписи/WORM |
| Обрезка цепочки | Независимый ожидаемый checkpoint | test_audit_tamper_and_truncation | Доверие к checkpoint внешнее |
| XSS | Экранирование и CSP | tools/ui_smoke.py | Базовый прогон CI пройден; полный XSS аудит не выполнен |
| DoS | Body 1 МиБ, event 16 КиБ, batch 100, login limit | test_bad_event_time_and_oversize | Нет общих tenant quotas, bounded HTTP thread pool |

Не подключать реальные production endpoints. Использовать синтетические данные. Это граница применимости стенда, а не дополнительное разрешение на выполнение каких-либо действий.

Проверки 0.2.0: `test_events_alerts_cases_evidence_responses_share_scope`, `test_audit_export_rules_replay_cannot_bypass_scopes`, `test_stale_principal_cannot_mutate_after_revocation`, `test_policy_change_blocks_inflight_request`. Доступ ограничивается атрибутами актива, а не анализом содержимого произвольного поля event attributes.
