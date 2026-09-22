"""投递状态通知（DSN，RFC 3464）解析（``GET /messages/{id}/delivery-report``）。

本模块是**纯只读**的解析：输入为 :func:`database.list_nodes`
返回的节点行（含 ``children_json`` / ``headers_json`` / ``text_content``
与 ``blob_sha256``），不回写任何记录、不依赖归档时未保存的派
生数据，因此对历史归档数据同样适用。

作用域识别（RFC 6522）：

* 只在已归档 MIME 树中识别 ``Content-Type: multipart/report;
  report-type=delivery-status`` 的节点作为**作用域**（媒体类型与
  ``report-type`` 参数均大小写无关）；其他 report-type
  （如 disposition-notification）与非 report 容器一律忽略；
* 仅解析作用域的**直接子件**中类型恰为
  ``message/delivery-status`` 的那一个：多于一个 →
  ``DUPLICATE_DELIVERY_STATUS``（422），一个都没有 →
  ``INVALID_DELIVERY_STATUS``（422）；不向内层后代串联，
  嵌套 multipart 内的状态件不算直接子件；
* 结果严格按 MIME 文档序（节点物化路径先根后子）给出。

``message/delivery-status`` 是叶子节点（归档为 blob），其解码字节
由调用方传入的 ``blob_loader`` 回调读取（内容寻址附件库），
取不到 → ``INVALID_DELIVERY_STATUS``（422，例如升级前归档、
未留存字节的历史数据）。

状态体语法（RFC 3464 §2）：

* 兼容 CRLF / LF / 裸 CR 换行与 RFC 5322 折叠行（续行以空白开头，
  折叠点并为一个空格）；
* 一个或多个**空行**分隔字段块：第一块为**每邮件（信封）块**，
  其后每块为**逐收件人块**；首尾空行忽略；
* 逐收件人块必须含 ``Final-Recipient``、``Action``、``Status``
  三个字段；``Action`` 取 RFC 3464 五个合法值之一，``Status``
  必须是三段数字（``class.subject.detail``）；
* ``Diagnostic-Code``、``Remote-MTA``、``Last-Attempt-Date``
  原样规范化保留（缺失为 null）。

任何结构 / 必填字段非法都抛 :class:`MIMEParseError`
（全局处理器转成带 ``node_path`` 的 422），``node_path`` 指向
出问题的状态子件（结构问题指向作用域容器）。
"""

from __future__ import annotations

import json
import re
import sqlite3
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Optional

from .errors import MIMEParseError
from .mimeparser import parse_content_type
from .related import json_loads_headers
from .security import path_order_key

# ---------------------------------------------------------------------------
# 常量（RFC 3464 / RFC 6522）
# ---------------------------------------------------------------------------

REPORT_MEDIA_TYPE = "multipart/report"
STATUS_MEDIA_TYPE = "message/delivery-status"
REPORT_TYPE_DELIVERY = "delivery-status"

# RFC 3464 §2.3：Action 字段的五个合法值（大小写无关比较）。
_VALID_ACTIONS = frozenset(
    {"failed", "delayed", "delivered", "relayed", "expanded"}
)

# RFC 3463 §2：增强状态码 class.subject.detail，三段均为 1..3 位数字。
# 归档场景只做“三段数字”的语法校验，不进一步强制 class ∈ 2/4/5。
_STATUS_RE = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")

# 每邮件（信封）块中保留的字段。
_ENVELOPE_FIELDS = frozenset(
    {
        "original-envelope-id",
        "reporting-mta",
        "received-from-mta",
        "arrival-date",
    }
)

# 逐收件人块的必填字段（RFC 3464 §2.2/2.3/2.4）。
_REQUIRED_RECIPIENT_FIELDS = ("final-recipient", "action", "status")

# 逐收件人块中额外保留的字段（RFC 3464 §2.3、§3，缺失输出 null）。
_RECIPIENT_OPTIONAL_FIELDS = (
    "diagnostic-code",
    "remote-mta",
    "last-attempt-date",
)

# DSN 字段名：RFC 3464 使用连字符 token，扩展字段以 X- 开头。
_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


# ---------------------------------------------------------------------------
# 结果数据结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeliveryEnvelope:
    """每邮件块（信封标识）。"""

    original_envelope_id: Optional[str] = None
    reporting_mta: Optional[str] = None
    received_from_mta: Optional[str] = None
    arrival_date: Optional[str] = None


@dataclass(frozen=True)
class DeliveryRecipient:
    """一个逐收件人块的标准化结果。"""

    final_recipient: str  # "type; value" 中 value 部分（地址）
    final_recipient_type: str  # 地址类型（小写），如 "rfc822"
    action: str  # 小写合法值
    status: str  # 三段数字状态码原文
    diagnostic_code: Optional[str] = None  # 整个 "type; value" 原文
    remote_mta: Optional[str] = None
    last_attempt_date: Optional[str] = None


@dataclass
class DeliveryReport:
    """一个 multipart/report 投递状态作用域的解析结果。"""

    scope_node_path: str  # multipart/report; report-type=delivery-status 节点
    report_node_path: str  # 其直接 message/delivery-status 子件
    envelope: DeliveryEnvelope
    recipients: list[DeliveryRecipient] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 作用域发现
# ---------------------------------------------------------------------------


def _content_type_with_params(
    row: sqlite3.Row,
) -> Optional[tuple[str, dict[str, str]]]:
    """重新严格解析节点的 Content-Type 头，返回 ``(小写媒体类型, 参数)``。

    归档只留存解码后的头值；结构参数均为 ASCII，重新编码解析与
    归档时等价。没有 Content-Type 头返回 None。
    """

    for name, value in json_loads_headers(row["headers_json"]):
        if name.lower() == "content-type":
            ct = parse_content_type(value.encode("utf-8"), row["path"])
            return ct.media_type, ct.params
    return None


def _children(
    by_path: dict[str, sqlite3.Row], row: sqlite3.Row
) -> list[sqlite3.Row]:
    return [by_path[p] for p in json.loads(row["children_json"])]


def _is_delivery_scope(row: sqlite3.Row) -> bool:
    """节点是否为 ``multipart/report; report-type=delivery-status``。"""

    parsed = _content_type_with_params(row)
    if parsed is None:
        return False
    media_type, params = parsed
    return (
        media_type == REPORT_MEDIA_TYPE
        and (params.get("report-type") or "").strip().lower()
        == REPORT_TYPE_DELIVERY
    )


def extract_delivery_reports(
    rows: list[sqlite3.Row],
    blob_loader: Callable[[str], Optional[bytes]],
) -> list[DeliveryReport]:
    """在一封已归档邮件的节点行上提取全部 DSN 投递状态报告。

    ``rows`` 为 :func:`database.list_nodes` 的结果（按文档序）。
    ``blob_loader`` 按 ``blob_sha256`` 从附件库取回状态子件的
    解码字节，取不到时返回 None。

    返回按 MIME 文档序排列的 :class:`DeliveryReport`；邮件中没有
    任何投递状态作用域时返回空列表。结构或必填字段非法抛
    :class:`MIMEParseError`。
    """

    by_path = {r["path"]: r for r in rows}
    reports: list[DeliveryReport] = []
    for row in sorted(rows, key=lambda r: path_order_key(r["path"])):
        if not _is_delivery_scope(row):
            continue

        # 仅识别直接子件中的 message/delivery-status：不向内层
        # 后代（嵌套 multipart / message/rfc822 封装件）串联。
        status_parts = [
            child
            for child in _children(by_path, row)
            if (child["content_type"] or "").lower() == STATUS_MEDIA_TYPE
        ]
        if len(status_parts) > 1:
            raise MIMEParseError(
                "DUPLICATE_DELIVERY_STATUS",
                "同一个 multipart/report 作用域内出现了多个直接"
                " message/delivery-status 状态子件",
                row["path"],
                {
                    "status_node_paths": [c["path"] for c in status_parts],
                },
            )
        if not status_parts:
            raise MIMEParseError(
                "INVALID_DELIVERY_STATUS",
                "multipart/report; report-type=delivery-status 作用域"
                " 缺少直接 message/delivery-status 子件",
                row["path"],
            )

        status_row = status_parts[0]
        raw = _load_status_bytes(status_row, blob_loader)
        envelope, recipients = parse_delivery_status(raw, status_row["path"])
        reports.append(
            DeliveryReport(
                scope_node_path=row["path"],
                report_node_path=status_row["path"],
                envelope=envelope,
                recipients=recipients,
            )
        )
    return reports


def _load_status_bytes(
    row: sqlite3.Row,
    blob_loader: Callable[[str], Optional[bytes]],
) -> bytes:
    """取状态叶子的解码内容：text 叶子取文本，blob 叶子回附件库。"""

    if row["kind"] == "text" and row["text_content"] is not None:
        return row["text_content"].encode("utf-8")
    blob_sha = row["blob_sha256"]
    if blob_sha:
        content = blob_loader(blob_sha)
        if content is not None:
            return content
    raise MIMEParseError(
        "INVALID_DELIVERY_STATUS",
        "message/delivery-status 子件的解码内容不可用"
        "（可能为升级前归档、未留存字节的历史数据）",
        row["path"],
    )


# ---------------------------------------------------------------------------
# message/delivery-status 正文解析（RFC 3464 §2）
# ---------------------------------------------------------------------------


def parse_delivery_status(
    raw: bytes, node_path: str
) -> tuple[DeliveryEnvelope, list[DeliveryRecipient]]:
    """解析一个 ``message/delivery-status`` 叶子的解码字节。

    返回 ``(每邮件信封块, 逐收件人块列表（文档序）)``。空状态体、
    字段结构非法、必填字段缺失/非法时抛 :class:`MIMEParseError`。
    """

    text = _decode_status_text(raw)
    blocks = _split_blocks(text, node_path)
    if not blocks:
        raise MIMEParseError(
            "INVALID_DELIVERY_STATUS",
            "message/delivery-status 内容为空：至少需要每邮件块",
            node_path,
        )

    # 第一块：每邮件块（信封标识）。
    envelope_fields = _parse_field_block(
        blocks[0], node_path, block_index=0
    )
    envelope = DeliveryEnvelope(
        original_envelope_id=envelope_fields.get("original-envelope-id"),
        reporting_mta=envelope_fields.get("reporting-mta"),
        received_from_mta=envelope_fields.get("received-from-mta"),
        arrival_date=envelope_fields.get("arrival-date"),
    )

    # 其余块：逐收件人块。
    recipients: list[DeliveryRecipient] = []
    for idx, block in enumerate(blocks[1:], start=1):
        recipients.append(
            _parse_recipient_block(block, node_path, block_index=idx)
        )
    if not recipients:
        raise MIMEParseError(
            "INVALID_DELIVERY_STATUS",
            "message/delivery-status 缺少逐收件人块",
            node_path,
        )

    return envelope, recipients


def _decode_status_text(raw: bytes) -> str:
    """DSN 为纯文本：先 UTF-8 后 latin-1 兜底（与脏头字面量策略一致）。"""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    # 统一换行：CRLF / 裸 CR 一律归一为 LF。
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _split_blocks(text: str, node_path: str) -> list[str]:
    """按一个或多个空行切分字段块，首尾空行忽略。

    先做 RFC 5322 去折叠（以 WSP 开头的物理行折到上一行，折叠点
    并为一个空格），再按空行切块。空块（被连续空行夹出的内容为空
    的块）属于结构非法：首尾之外不允许出现。
    """

    lines = text.split("\n")
    unfolded: list[str] = []
    for line in lines:
        if line[:1] in (" ", "\t") and unfolded:
            # RFC 5322 unfolding：折叠点（换行 + WSP）替换为一个空格。
            unfolded[-1] = unfolded[-1] + " " + line
        else:
            unfolded.append(line)

    blocks: list[str] = []
    current: list[str] = []
    for line in unfolded:
        if line.strip() == "":
            if current:
                blocks.append("\n".join(current))
                current = []
            continue
        current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def _normalize_value(value: str) -> str:
    """字段值规范化：NFC，线性空白（空格/TAB/换行）压缩并去两端。"""

    return unicodedata.normalize(
        "NFC", re.sub(r"[ \t\n]+", " ", value).strip(" \t")
    )


def _parse_field_block(
    block: str, node_path: str, *, block_index: int
) -> dict[str, str]:
    """把一个字段块解析为 ``{小写字段名: 规范化值}``。

    字段名必须是合法 token（非空、不含 ':' 与控制字符）；已知字段
    在同一块内重复即结构非法（DSN 字段在每块中至多出现一次）。
    """

    fields: dict[str, str] = {}
    for line_no, line in enumerate(block.split("\n"), start=1):
        # _split_blocks 已去折叠；到达这里的行不再以 WSP 开头。
        colon = line.find(":")
        if colon <= 0:
            raise MIMEParseError(
                "INVALID_DELIVERY_STATUS",
                "message/delivery-status 字段行缺少 ':' 或字段名为空",
                node_path,
                {
                    "block": block_index,
                    "line": line.strip()[:80],
                },
            )
        name = line[:colon].strip().lower()
        if not _FIELD_NAME_RE.match(name):
            raise MIMEParseError(
                "INVALID_DELIVERY_STATUS",
                f"message/delivery-status 字段名非法: {name!r}",
                node_path,
                {"block": block_index, "field": name},
            )
        value = _normalize_value(line[colon + 1:])
        if not value:
            raise MIMEParseError(
                "INVALID_DELIVERY_STATUS",
                f"message/delivery-status 字段 {name!r} 的值为空",
                node_path,
                {"block": block_index, "field": name},
            )
        if name in fields:
            raise MIMEParseError(
                "INVALID_DELIVERY_STATUS",
                f"message/delivery-status 字段 {name!r} 在同一块内重复",
                node_path,
                {"block": block_index, "field": name},
            )
        fields[name] = value
    return fields


def _split_typed_value(
    value: str, node_path: str, *, block_index: int, field: str
) -> tuple[str, str]:
    """拆 RFC 3464 的 ``address-type; address`` 形态字段。

    分号两侧都必须非空。地址类型规范化为小写（RFC 3464：类型名
    大小写无关），地址值保持规范化原文（不强制小写邮箱域——
    DSN 里的地址可能是网关后的非 RFC 822 形式，留给客户端判断）。
    """

    type_part, sep, addr = value.partition(";")
    addr_type = type_part.strip().lower()
    address = addr.strip()
    if not sep or not addr_type or not address:
        raise MIMEParseError(
            "INVALID_DELIVERY_STATUS",
            f"message/delivery-status 字段 {field!r} 必须是"
            " 'type; value' 形式且两侧非空",
            node_path,
            {"block": block_index, "field": field, "value": value},
        )
    return addr_type, address


def _parse_recipient_block(
    block: str, node_path: str, *, block_index: int
) -> DeliveryRecipient:
    fields = _parse_field_block(block, node_path, block_index=block_index)

    # 必填字段存在性。
    missing = [
        name
        for name in _REQUIRED_RECIPIENT_FIELDS
        if name not in fields
    ]
    if missing:
        raise MIMEParseError(
            "INVALID_DELIVERY_STATUS",
            "逐收件人块缺少必填字段: " + ", ".join(missing),
            node_path,
            {"block": block_index, "missing": missing},
        )

    # Final-Recipient（RFC 3464 §2.2）：type; value。
    rcpt_type, rcpt_addr = _split_typed_value(
        fields["final-recipient"],
        node_path,
        block_index=block_index,
        field="final-recipient",
    )

    # Action（RFC 3464 §2.3）：五个合法值之一。
    action = fields["action"].lower()
    if action not in _VALID_ACTIONS:
        raise MIMEParseError(
            "INVALID_DELIVERY_STATUS",
            f"Action 字段值非法: {fields['action']!r}（合法值为 "
            "failed / delayed / delivered / relayed / expanded）",
            node_path,
            {"block": block_index, "field": "action", "value": action},
        )

    # Status（RFC 3463 §2）：三段数字。
    status = fields["status"]
    if not _STATUS_RE.match(status):
        raise MIMEParseError(
            "INVALID_DELIVERY_STATUS",
            f"Status 字段不是三段数字增强状态码: {status!r}",
            node_path,
            {"block": block_index, "field": "status", "value": status},
        )

    return DeliveryRecipient(
        final_recipient=rcpt_addr,
        final_recipient_type=rcpt_type,
        action=action,
        status=status,
        diagnostic_code=fields.get("diagnostic-code"),
        remote_mta=fields.get("remote-mta"),
        last_attempt_date=fields.get("last-attempt-date"),
    )
