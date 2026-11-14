# План выполнения RFP R2

Полный объём сохраняется: 508 функциональных и 111 нефункциональных требований, 192 AT, 16 OMEGA E2E. Локальные тесты не заменяют формальную приёмку. Перечень всех идентификаторов и текущие статусы находятся в `acceptance/coverage.json`.

| Этап | Содержание | Условие завершения |
|---|---|---|
| 0.1.0 Local baseline | Транзакционный сквозной lab-контур | Локальные регрессии; **не завершает M1** |
| 0.2.0 Access Control | Лабораторные identities, ротация, сеансы, application ABAC, schema migration | Локальные тесты; **Identity/M1 не завершён** |
| Identity completion | PostgreSQL/RLS, OIDC Code+PKCE, MFA assurance, подписанные политики | IAM/TEN P0 и отрицательные тесты всех ресурсов |
| 0.3.0 Durable telemetry (local) | Реестр источников, квоты, изоляция ошибок, DLQ/retry, показатели очереди | Локальные регрессии; промышленный ingestion не завершён |
| Telemetry completion | Gateway, mTLS enrollment, schema registry, внешний broker | ACK/replay/poison/fairness с реальными инфраструктурными отказами |
| 0.4.0 Local Collector | Foreground heartbeat, SQLite spool, ACK/retry, локальные счётчики и CLI | Локальные регрессии Windows/Linux; endpoint baseline не завершён |
| Endpoint completion | Windows/Linux службы, Event Log/ETW/auditd, encrypted spool, signed update | Совместимость ОС и 24-часовые ресурсные прогоны |
| 0.5.0 Rule Lab and Search | Фильтры, курсор UI, AND/OR, fixtures, snapshot replay | Локальные регрессии; промышленная аналитика не завершена |
| Analytics completion | ClickHouse/search, temporal rules, watermark, replay jobs | Quality suite и R1 search benchmark |
| 0.6.0 Evidence и response | PKI/KMS, immutable vault, signatures, agent receipts, bounded reversible actions | Quorum/MFA, TTL, rollback и offline verifier с trust anchor |
| 0.7.0 Posture | SBOM/vulnerabilities, CMDB, webhooks, risk and remediation | Import idempotency и provenance |
| OMEGA P4–P8 | Graph/hunting, NDR, cloud/Kubernetes/identity, OT/email/TI, SOAR, UEBA/ML | Изолированные модули, replay, safety и privacy gates |
| OMEGA P9–P10 | Region federation, fencing, KMS grants, supply chain, compliance | DR game days, residency, signed provenance |
| OMEGA P11 | Полная эксплуатационная приёмка | Все AT/E2E, независимая проверка, документация и передача |

Числа 12k EPS R1, 85k steady EPS и 300k surge EPS R2 остаются целевыми показателями, а не результатами этой версии. Нельзя закрывать performance-пункты по unit-тестам SQLite. Нельзя закрывать WIN/MAC signing по сборке исходников без сертификатов, entitlement и проверки на соответствующих ОС.

Ближайший блокирующий результат: промышленная IAM-модель и PostgreSQL tenant enforcement. До него запрещено считать любую версию production-ready, даже если демонстрационный UI выглядит завершённым.
