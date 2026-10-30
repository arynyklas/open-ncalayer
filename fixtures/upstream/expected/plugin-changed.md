Плагин оригинала **Example demo** (`kz.example.demo`): 1.0.0 → 1.1.0, дата наблюдения 2026-10-31.

| Поле | До | После |
|---|---|---|
| version | 1.0.0 | 1.1.0 |
| url | http://upstream.test/updates/bundles/bundle-a.jar | http://upstream.test/updates/bundles/bundle-a.jar |
| hash | 5a8f2ee5b84a80fa | a2ce7f6deb14d4fe |
| csernum |  |  |
| chash |  |  |

> synthetic plugin

Подпись JAR совпадает с `csernum`/`chash` манифеста: не проверено.

Порт: `plugins/demo`, портирована версия 1.0.0.

### API

| Что | Изменение | Значение |
|---|---|---|
| метод kz.example.demo.DemoModule | добавлено | `verify(Ljava/lang/String;)Ljava/lang/String;` |
| поле kz.example.demo.DemoModule | добавлено | `VERIFY_FAILED:Ljava/lang/String;` |
| NCALayerMethod | добавлено | `kz.example.demo.DemoModule.verify(Ljava/lang/String;)Ljava/lang/String;` |
| код ошибки | добавлено | `VERIFY_FAILED` |

Факты записи: https://github.com/example/open-ncalayer/tree/upstream/history/2026-10-31-1.5-0123abcd/

- [ ] Проверить API-diff
- [ ] Обновить порт или реестр
- [ ] Обновить эталоны в приватной лаборатории

<!-- upstream-key: plugin:kz.example.demo:1.1.0 -->
