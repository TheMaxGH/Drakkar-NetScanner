"""Разбор сетевых пакетов для DRAKKAR NetScanner.

Модуль отделяет низкоуровневые объекты Scapy от интерфейса приложения.
В GUI передаются обычные структуры данных, поэтому поток интерфейса не
зависит от внутреннего устройства пакета и может быстро обновлять таблицу.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP, Dot3, Ether, LLC
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


@dataclass(slots=True)
class PacketRecord:
    """Безопасное представление пакета для отображения в интерфейсе."""

    номер: int
    время: str
    метка_секунды: int
    источник: str
    назначение: str
    протокол: str
    длина: int
    информация: str
    слои: list[dict[str, Any]] = field(default_factory=list)

    def как_строка(self, колонка: int) -> str:
        """Возвращает значение для колонки табличной модели."""

        значения = (
            self.номер,
            self.время,
            self.источник,
            self.назначение,
            self.протокол,
            self.длина,
            self.информация,
        )
        return str(значения[колонка])


def разобрать_пакет(пакет: Packet, номер: int) -> PacketRecord:
    """Извлекает из Scapy-пакета поля, необходимые для анализа трафика."""

    время_пакета = datetime.fromtimestamp(float(пакет.time))
    протокол = _определить_протокол(пакет)
    источник, назначение = _получить_адреса(пакет)
    информация = _сформировать_описание(пакет, протокол)
    слои = _разобрать_слои(пакет)

    return PacketRecord(
        номер=номер,
        время=время_пакета.strftime("%H:%M:%S.%f")[:-3],
        метка_секунды=int(float(пакет.time)),
        источник=источник,
        назначение=назначение,
        протокол=протокол,
        длина=len(пакет),
        информация=информация,
        слои=слои,
    )


def _получить_адреса(пакет: Packet) -> tuple[str, str]:
    """Возвращает адреса отправителя и получателя для IPv4/IPv6/канального уровня."""

    if IP in пакет:
        return str(пакет[IP].src), str(пакет[IP].dst)
    if IPv6 in пакет:
        return str(пакет[IPv6].src), str(пакет[IPv6].dst)

    источник = getattr(пакет, "src", "неизвестно")
    назначение = getattr(пакет, "dst", "неизвестно")
    return str(источник), str(назначение)


def _определить_протокол(пакет: Packet) -> str:
    """Определяет прикладной или транспортный протокол пакета."""

    if DNS in пакет:
        return "DNS"
    if HTTPRequest in пакет or HTTPResponse in пакет:
        return "HTTP"
    if TCP in пакет:
        return "TCP"
    if UDP in пакет:
        return "UDP"
    if ICMP in пакет:
        return "ICMP"
    if ARP in пакет:
        return "ARP"
    if IP in пакет:
        return f"IP-{пакет[IP].proto}"
    if IPv6 in пакет:
        return "IPv6"
    if LLC in пакет or Dot3 in пакет:
        return "LLC"
    if Ether in пакет:
        return "Ethernet"
    return пакет.__class__.__name__


def _сформировать_описание(пакет: Packet, протокол: str) -> str:
    """Создает краткое, человекочитаемое описание содержимого пакета."""

    if DNS in пакет:
        dns = пакет[DNS]
        запрос = ""
        if dns.qd and DNSQR in dns:
            запрос = dns[DNSQR].qname.decode(errors="replace").rstrip(".")
        тип = "ответ" if dns.qr else "запрос"
        return f"DNS {тип} {запрос}".strip()

    if HTTPRequest in пакет:
        http = пакет[HTTPRequest]
        метод = _bytes_to_text(getattr(http, "Method", b""))
        узел = _bytes_to_text(getattr(http, "Host", b""))
        путь = _bytes_to_text(getattr(http, "Path", b""))
        return f"HTTP запрос {метод} {узел}{путь}".strip()

    if HTTPResponse in пакет:
        http = пакет[HTTPResponse]
        код = _bytes_to_text(getattr(http, "Status_Code", b""))
        причина = _bytes_to_text(getattr(http, "Reason_Phrase", b""))
        return f"HTTP ответ {код} {причина}".strip()

    if TCP in пакет:
        tcp = пакет[TCP]
        флаги = str(tcp.sprintf("%TCP.flags%"))
        return f"TCP {tcp.sport} -> {tcp.dport}, флаги: {флаги}"

    if UDP in пакет:
        udp = пакет[UDP]
        return f"UDP {udp.sport} -> {udp.dport}"

    if ICMP in пакет:
        icmp = пакет[ICMP]
        return f"ICMP тип {icmp.type}, код {icmp.code}"

    if ARP in пакет:
        arp = пакет[ARP]
        действие = "запрос" if arp.op == 1 else "ответ" if arp.op == 2 else f"операция {arp.op}"
        return f"ARP {действие}: {arp.psrc} -> {arp.pdst}"

    if LLC in пакет or Dot3 in пакет:
        return f"Канальный кадр LLC, {len(пакет)} байт"

    if Ether in пакет:
        ether = пакет[Ether]
        return f"Ethernet {ether.src} -> {ether.dst}, тип {hex(ether.type)}"

    return f"{протокол}, {len(пакет)} байт"


def _разобрать_слои(пакет: Packet) -> list[dict[str, Any]]:
    """Преобразует уровни Scapy в список словарей для дерева деталей."""

    результат: list[dict[str, Any]] = []
    текущий = пакет
    while isinstance(текущий, Packet):
        поля = {
            имя: _значение_для_интерфейса(значение)
            for имя, значение in текущий.fields.items()
        }
        результат.append({"имя": текущий.name, "поля": поля})
        следующий = текущий.payload
        if следующий is None or следующий is текущий:
            break
        if следующий.__class__.__name__ in {"NoPayload", "Padding"}:
            break
        текущий = следующий
    return результат


def _значение_для_интерфейса(значение: Any) -> str:
    """Ограничивает объем данных, чтобы дерево деталей оставалось отзывчивым."""

    if isinstance(значение, bytes):
        текст = значение.hex(" ")
    else:
        текст = str(значение)
    if len(текст) > 240:
        return f"{текст[:240]}..."
    return текст


def _bytes_to_text(значение: Any) -> str:
    """Безопасно декодирует байтовые поля HTTP/DNS."""

    if isinstance(значение, bytes):
        return значение.decode("utf-8", errors="replace")
    return str(значение)
