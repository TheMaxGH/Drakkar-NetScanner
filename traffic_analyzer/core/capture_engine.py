"""Поток захвата пакетов DRAKKAR NetScanner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ctypes.util
import sys
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import conf, get_if_list, sniff, wrpcap
try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None
from scapy.error import Scapy_Exception
from scapy.packet import Packet

from .parser import PacketRecord, разобрать_пакет

NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"


@dataclass(frozen=True, slots=True)
class NetworkInterface:
    """Описание сетевого интерфейса для понятного отображения в GUI."""

    имя: str
    подпись: str
    описание: str = ""
    mac: str = ""
    адреса: tuple[str, ...] = ()


def получить_интерфейсы() -> list[NetworkInterface]:
    """Возвращает список доступных интерфейсов с понятными подписями."""

    scapy_interfaces = _получить_scapy_интерфейсы()
    if scapy_interfaces:
        return scapy_interfaces

    windows_interfaces = _получить_windows_интерфейсы()
    if windows_interfaces:
        return windows_interfaces

    try:
        имена = sorted(get_if_list())
    except Scapy_Exception:
        имена = []

    интерфейсы = [
        NetworkInterface(имя=имя, подпись=_короткое_имя_интерфейса(имя))
        for имя in имена
    ]
    if conf.iface:
        основной = str(conf.iface)
        if all(интерфейс.имя != основной for интерфейс in интерфейсы):
            интерфейсы.insert(
                0,
                NetworkInterface(имя=основной, подпись=_короткое_имя_интерфейса(основной)),
            )
    return интерфейсы


def npcap_установлен() -> bool:
    """Проверяет наличие Npcap/WinPcap на Windows.

    На Linux и macOS функция возвращает True, потому что там используется
    системный libpcap и отдельная установка Npcap не требуется.
    """

    if not sys.platform.startswith("win"):
        return True

    возможные_файлы = (
        Path(r"C:\Windows\System32\Npcap\wpcap.dll"),
        Path(r"C:\Windows\System32\Npcap\Packet.dll"),
        Path(r"C:\Windows\System32\wpcap.dll"),
        Path(r"C:\Windows\SysWOW64\Npcap\wpcap.dll"),
    )
    if any(файл.exists() for файл in возможные_файлы):
        return True

    return bool(ctypes.util.find_library("wpcap") or ctypes.util.find_library("Packet"))


def _получить_scapy_интерфейсы() -> list[NetworkInterface]:
    """Получает интерфейсы из реестра Scapy/Npcap без служебных фильтров."""

    результат: list[NetworkInterface] = []
    try:
        raw_interfaces = list(conf.ifaces.values())
    except (AttributeError, Scapy_Exception, OSError):
        raw_interfaces = []

    for item in raw_interfaces:
        имя = str(getattr(item, "network_name", "") or getattr(item, "name", "")).strip()
        имя_windows = str(getattr(item, "name", "") or "").strip()
        описание = str(getattr(item, "description", "") or "").strip()
        if not имя or _служебный_интерфейс(имя_windows, описание):
            continue

        адреса = _адреса_scapy_интерфейса(item)
        mac = str(getattr(item, "mac", "") or "").strip()
        подпись = _собрать_подпись_интерфейса(
            имя_windows or описание or имя,
            описание,
            адреса,
        )
        результат.append(
            NetworkInterface(
                имя=имя,
                подпись=подпись,
                описание=описание,
                mac=mac,
                адреса=адреса,
            )
        )

    return sorted(результат, key=_ключ_сортировки_интерфейса)


def _получить_windows_интерфейсы() -> list[NetworkInterface]:
    """Получает человекочитаемые имена адаптеров Windows через Scapy."""

    if get_windows_if_list is None:
        return []

    try:
        raw_interfaces = get_windows_if_list()
    except (Scapy_Exception, OSError, AttributeError):
        return []

    результат: list[NetworkInterface] = []
    seen: set[str] = set()
    for item in raw_interfaces:
        имя = str(item.get("name") or item.get("guid") or "").strip()
        if not имя or имя in seen or _служебный_интерфейс(имя, описание):
            continue
        seen.add(имя)

        описание = str(item.get("description") or "").strip()
        понятное_имя = str(item.get("name") or "").strip()
        mac = str(item.get("mac") or "").strip()
        адреса = tuple(str(ip) for ip in item.get("ips", []) if ip)
        подпись = _собрать_подпись_интерфейса(понятное_имя, описание, адреса)
        результат.append(
            NetworkInterface(
                имя=имя,
                подпись=подпись,
                описание=описание,
                mac=mac,
                адреса=адреса,
            )
        )
    return sorted(результат, key=lambda интерфейс: интерфейс.подпись.casefold())


def _адреса_scapy_интерфейса(item: object) -> tuple[str, ...]:
    """Извлекает IPv4/IPv6 адреса из объекта интерфейса Scapy."""

    ips = getattr(item, "ips", {})
    адреса: list[str] = []
    if isinstance(ips, dict):
        for values in ips.values():
            адреса.extend(str(value) for value in values if value)
    ip = getattr(item, "ip", None)
    if ip:
        адреса.insert(0, str(ip))
    return tuple(dict.fromkeys(адреса))


def _служебный_интерфейс(имя: str, описание: str) -> bool:
    """Отбрасывает промежуточные драйверы и фильтры Windows."""

    текст = f"{имя} {описание}".casefold()
    маркеры = (
        "wan miniport",
        "npcap packet driver",
        "qos packet scheduler",
        "wfp",
        "lightweight filter",
        "virtual switch extension filter",
    )
    return any(маркер in текст for маркер in маркеры)


def _ключ_сортировки_интерфейса(интерфейс: NetworkInterface) -> tuple[int, str]:
    """Ставит реальные адаптеры с IPv4 выше виртуальных и loopback."""

    подпись = интерфейс.подпись.casefold()
    has_ipv4 = any("." in адрес and not адрес.startswith("127.") for адрес in интерфейс.адреса)
    virtual = any(word in подпись for word in ("loopback", "virtual", "туннель", "tunnel"))
    return (0 if has_ipv4 and not virtual else 1 if has_ipv4 else 2, подпись)


def _собрать_подпись_интерфейса(
    имя: str,
    описание: str,
    адреса: tuple[str, ...],
) -> str:
    """Формирует короткую подпись без пугающего NPF/GUID, но с IP-адресами."""

    основа = описание or _короткое_имя_интерфейса(имя)
    ip_адреса = [адрес for адрес in адреса if "." in адрес and not адрес.startswith("169.254.")]
    if ip_адреса:
        return f"{основа} ({', '.join(ip_адреса[:2])})"
    return основа


def _короткое_имя_интерфейса(имя: str) -> str:
    """Сокращает техническое имя интерфейса до читаемого вида."""

    if "\\Device\\NPF_" in имя:
        return имя.replace("\\Device\\NPF_", "Адаптер ")
    return имя


class PacketCaptureThread(QThread):
    """QThread, выполняющий захват пакетов без блокировки GUI."""

    packet_captured = pyqtSignal(object, object)
    capture_error = pyqtSignal(str)
    capture_status = pyqtSignal(str)

    def __init__(
        self,
        интерфейс: str,
        bpf_фильтр: str = "",
        лимит_памяти: int = 50000,
        родитель: Optional[object] = None,
    ) -> None:
        super().__init__(родитель)
        self.интерфейс = интерфейс
        self.bpf_фильтр = bpf_фильтр.strip()
        self.лимит_памяти = лимит_памяти
        self._работает = False
        self._номер = 0
        self._сырые_пакеты: list[Packet] = []

    def run(self) -> None:
        """Запускает цикл захвата Scapy в отдельном потоке Qt."""

        self._работает = True
        self.capture_status.emit("Захват запущен")
        try:
            while self._работает:
                sniff(
                    iface=self.интерфейс or None,
                    filter=self.bpf_фильтр or None,
                    prn=self._обработать_пакет,
                    store=False,
                    timeout=1,
                    stop_filter=self._нужно_остановить,
                )
        except PermissionError:
            self.capture_error.emit(
                "Недостаточно прав для захвата пакетов. "
                "Запустите приложение от имени администратора."
            )
        except Scapy_Exception as ошибка:
            self.capture_error.emit(f"Ошибка Scapy: {ошибка}")
        except OSError as ошибка:
            self.capture_error.emit(f"Системная ошибка захвата: {ошибка}")
        finally:
            self._работает = False
            self.capture_status.emit("Захват остановлен")

    def stop(self) -> None:
        """Инициирует мягкую остановку потока захвата."""

        self._работает = False

    def экспортировать_pcap(self, путь: str | Path) -> int:
        """Сохраняет уже захваченные пакеты в PCAP-файл и возвращает их количество."""

        файл = Path(путь)
        файл.parent.mkdir(parents=True, exist_ok=True)
        снимок = list(self._сырые_пакеты)
        if снимок:
            wrpcap(str(файл), снимок)
        else:
            файл.write_bytes(b"")
        return len(снимок)

    def очистить_буфер(self) -> None:
        """Очищает внутренний PCAP-буфер после очистки интерфейса."""

        self._сырые_пакеты.clear()
        self._номер = 0

    def _обработать_пакет(self, пакет: Packet) -> None:
        """Парсит пакет и отправляет результат в поток интерфейса."""

        if not self._работает:
            return

        self._номер += 1
        запись: PacketRecord = разобрать_пакет(пакет, self._номер)
        self._сырые_пакеты.append(пакет)
        if len(self._сырые_пакеты) > self.лимит_памяти:
            del self._сырые_пакеты[: len(self._сырые_пакеты) - self.лимит_памяти]
        self.packet_captured.emit(запись, пакет)

    def _нужно_остановить(self, _пакет: Packet) -> bool:
        """Проверяется Scapy после каждого пакета для завершения sniff."""

        return not self._работает
