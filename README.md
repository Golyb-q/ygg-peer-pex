# Yggdrasil PEX

Автоматический обмен публичными пирами `Peers:[]` для [Yggdrasil](https://yggdrasil-network.github.io/).

Находит пиры через `NodeInfo`, проверяет, сохраняет рабочие и делится ими через свой `NodeInfo`.

## Установка

```bash
sudo python3 ygg-peer-pex.py install
sudo systemctl enable --now ygg-peer-pex.timer
```

Каждые 3 часа: поиск новых пиров, удаление неработающих, обновление `pex.internet`.

## Команды

```bash
# Запустить сейчас
sudo python3 ygg-peer-pex.py --discover --prune-down

# Установить с автоперезапуском Yggdrasil при изменениях
sudo python3 ygg-peer-pex.py install --restart

# Логи
journalctl -u ygg-peer-pex.service -e

# Удалить
sudo python3 ygg-peer-pex.py uninstall
```

Изменения `NodeInfo` применяются после перезапуска Yggdrasil.

**Требования:** Linux, systemd, Python 3, Yggdrasil 0.5.x.
