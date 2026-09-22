"""投递状态通知（GET /messages/{id}/delivery-report，RFC 3464 DSN）测试。

覆盖：multipart/report; report-type=delivery-status 作用域识别、
直接 message/delivery-status 子件解析、每邮件块/逐收件人块按空行
切分、CRLF/LF/裸 CR 与折叠行兼容、Final-Recipient/Action/Status
校验与标准化、Diagnostic-Code/Remote-MTA/Last-Attempt-Date 保留、
多收件人/多作用域文档序、非 delivery report-type 与嵌套状态件
忽略、404/空列表、422（多个/缺少状态子件、结构与必填字段非法）、
只读不改写。
"""

import base64

from conftest import make_multipart


# ---------------------------------------------------------------------------
# 构造辅助
# ---------------------------------------------------------------------------


def dsn_status_body(
    envelope: list[tuple[str, str]] | None = None,
    *recipients: list[tuple[str, str]],
    nl: str = "\r\n",
) -> bytes:
    """组装 message/delivery-status 叶子内容。

    块之间用一个空行分隔；缺省信封块给出 Reporting-MTA。
    """

    if envelope is None:
        envelope = [("Reporting-MTA", "dns; mr.example.com")]

    def block(fields: list[tuple[str, str]]) -> bytes:
        return nl.join(f"{k}: {v}" for k, v in fields).encode()

    chunks = [block(envelope)]
    for rcpt in recipients:
        chunks.append(block(rcpt))
    return (nl + nl).encode().join(chunks)


def dsn_part(
    body: bytes,
    *,
    cte: str | None = None,
    ctype: str = "message/delivery-status",
) -> bytes:
    head = f"Content-Type: {ctype}\r\n".encode()
    if cte:
        head += f"Content-Transfer-Encoding: {cte}\r\n".encode()
    payload = body
    if cte == "base64":
        payload = base64.b64encode(body) + b"\r\n"
    return head + b"\r\n" + payload


def human_part(text: str = "Delivery status notification") -> bytes:
    return (
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n" + text.encode()
    )


def report_container(
    status_body: bytes,
    *,
    extra_parts: list[bytes] | None = None,
    report_type: str = "delivery-status",
    boundary: str = "RPT",
    status_cte: str | None = None,
    status_ctype: str = "message/delivery-status",
) -> bytes:
    """multipart/report 容器（作为外层 multipart 的一个子件原始字节）。"""

    parts = [human_part(), dsn_part(status_body, cte=status_cte,
                                    ctype=status_ctype)]
    if extra_parts:
        parts.extend(extra_parts)
    body = make_multipart(parts, boundary)
    return (
        f"Content-Type: multipart/report;"
        f" report-type={report_type}; boundary={boundary}\r\n\r\n".encode()
        + body
    )


def message_with_parts(*parts: bytes, boundary: str = "MIX") -> bytes:
    return (
        b"Subject: delivery test\r\n"
        + f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n".encode()
        + make_multipart(list(parts), boundary)
    )


def post(client, data: bytes) -> int:
    r = client.post("/messages", content=data)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def delivery(client, mid: int):
    r = client.get(f"/messages/{mid}/delivery-report")
    assert r.status_code == 200, r.text
    return r.json()


FAILED_RCPT = [
    ("Final-Recipient", "RFC822; bob@example.org"),
    ("Action", "failed"),
    ("Status", "5.1.1"),
    ("Remote-MTA", "dns; mx.example.org"),
    ("Diagnostic-Code", "smtp;550 5.1.1 User unknown"),
    ("Last-Attempt-Date", "Mon, 01 Jan 2024 10:05:00 +0000"),
]

ENVELOPE = [
    ("Reporting-MTA", "dns; mr.example.com"),
    ("Received-From-MTA", "dns; relay.example.net"),
    ("Arrival-Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
    ("Original-Envelope-Id", "ENVID42"),
]


# ---------------------------------------------------------------------------
# 基本解析
# ---------------------------------------------------------------------------


def test_basic_delivery_report(client):
    body = dsn_status_body(ENVELOPE, FAILED_RCPT)
    mid = post(client, message_with_parts(report_container(body)))
    data = delivery(client, mid)
    assert data["id"] == mid
    assert len(data["reports"]) == 1

    report = data["reports"][0]
    # 外层 mixed 根 ""，唯一子件（第 1 个）是 multipart/report，
    # 其第 2 个直接子件是 message/delivery-status。
    assert report["scope_node_path"] == "1"
    assert report["report_node_path"] == "1/2"

    env = report["envelope"]
    assert env["original_envelope_id"] == "ENVID42"
    assert env["reporting_mta"] == "dns; mr.example.com"
    assert env["received_from_mta"] == "dns; relay.example.net"
    assert env["arrival_date"] == "Mon, 01 Jan 2024 10:00:00 +0000"

    assert len(report["recipients"]) == 1
    rcp = report["recipients"][0]
    assert rcp == {
        "final_recipient": "bob@example.org",
        "final_recipient_type": "rfc822",
        "action": "failed",
        "status": "5.1.1",
        "diagnostic_code": "smtp;550 5.1.1 User unknown",
        "remote_mta": "dns; mx.example.org",
        "last_attempt_date": "Mon, 01 Jan 2024 10:05:00 +0000",
    }


def test_multiple_recipients_in_document_order(client):
    delayed = [
        ("Final-Recipient", "rfc822; carol@example.org"),
        ("Action", "DELAYED"),
        ("Status", "4.7.1"),
    ]
    delivered = [
        ("Final-Recipient", "rfc822; dave@example.org"),
        ("Action", "delivered"),
        ("Status", "2.0.0"),
    ]
    body = dsn_status_body(None, FAILED_RCPT, delayed, delivered)
    mid = post(client, message_with_parts(report_container(body)))
    rcpts = delivery(client, mid)["reports"][0]["recipients"]
    assert [r["final_recipient"] for r in rcpts] == [
        "bob@example.org",
        "carol@example.org",
        "dave@example.org",
    ]
    # Action 大小写归一
    assert rcpts[1]["action"] == "delayed"
    # 缺省的可选字段为 null
    assert rcpts[1]["remote_mta"] is None
    assert rcpts[1]["diagnostic_code"] is None
    assert rcpts[1]["last_attempt_date"] is None
    # Final-Recipient 类型大小写归一为小写
    assert rcpts[0]["final_recipient_type"] == "rfc822"


def test_all_five_actions_accepted(client):
    for action in ("failed", "delayed", "delivered", "relayed", "expanded"):
        rcpt = [
            ("Final-Recipient", "rfc822; x@example.org"),
            ("Action", action),
            ("Status", "2.0.0"),
        ]
        mid = post(client, message_with_parts(report_container(
            dsn_status_body(None, rcpt))))
        got = delivery(client, mid)["reports"][0]["recipients"][0]
        assert got["action"] == action


def test_lf_and_bare_cr_line_endings(client):
    for nl in ("\n", "\r"):
        body = dsn_status_body(ENVELOPE, FAILED_RCPT, nl=nl)
        mid = post(client, message_with_parts(report_container(body)))
        report = delivery(client, mid)["reports"][0]
        assert report["recipients"][0]["status"] == "5.1.1"
        assert report["envelope"]["original_envelope_id"] == "ENVID42"


def test_folded_continuation_lines(client):
    # Diagnostic-Code 跨折叠行；Last-Attempt-Date 也折叠
    body = (
        b"Reporting-MTA: dns; mr.example.com\r\n"
        b"\r\n"
        b"Final-Recipient: rfc822; bob@example.org\r\n"
        b"Action: failed\r\n"
        b"Status: 5.1.1\r\n"
        b"Diagnostic-Code: smtp;\r\n"
        b" 550 5.1.1 User\r\n"
        b"\tunknown\r\n"
        b"Last-Attempt-Date: Mon,\r\n"
        b" 01 Jan 2024 10:05:00 +0000\r\n"
    )
    mid = post(client, message_with_parts(report_container(body)))
    rcp = delivery(client, mid)["reports"][0]["recipients"][0]
    assert rcp["diagnostic_code"] == "smtp; 550 5.1.1 User unknown"
    assert rcp["last_attempt_date"] == "Mon, 01 Jan 2024 10:05:00 +0000"


def test_status_part_with_base64_cte(client):
    body = dsn_status_body(ENVELOPE, FAILED_RCPT)
    mid = post(client, message_with_parts(
        report_container(body, status_cte="base64")))
    rcp = delivery(client, mid)["reports"][0]["recipients"][0]
    assert rcp["final_recipient"] == "bob@example.org"
    assert rcp["status"] == "5.1.1"


def test_status_part_with_quoted_printable_cte(client):
    # QP 软换行 + =3B（';'）编码，验证 CTE 先于 DSN 解析还原
    raw = (
        b"Reporting-MTA: dns; mr.example.com\r\n"
        b"\r\n"
        b"Final-Recipient: rfc822; b=\r\n"
        b"ob@example.org\r\n"
        b"Action: failed\r\n"
        b"Status: 5.1.1\r\n"
        b"Remote-MTA: dns=3B mx.example.org\r\n"
    )
    head = (
        b"Content-Type: message/delivery-status\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
    )
    raw_report = (
        b"Subject: bounce\r\n"
        b"Content-Type: multipart/report;"
        b" report-type=delivery-status; boundary=RPT\r\n\r\n"
        + make_multipart([human_part(), head + raw], "RPT")
    )
    mid = post(client, raw_report)
    rcp = delivery(client, mid)["reports"][0]["recipients"][0]
    assert rcp["final_recipient"] == "bob@example.org"
    assert rcp["remote_mta"] == "dns; mx.example.org"


def test_leading_and_trailing_blank_lines_ignored(client):
    body = (
        b"\r\n\r\n"
        b"Reporting-MTA: dns; mr.example.com\r\n"
        b"\r\n"
        b"Final-Recipient: rfc822; b@x.org\r\n"
        b"Action: failed\r\nStatus: 5.1.1\r\n"
        b"\r\n\r\n"
    )
    mid = post(client, message_with_parts(report_container(body)))
    rcp = delivery(client, mid)["reports"][0]["recipients"][0]
    assert rcp["final_recipient"] == "b@x.org"


def test_root_is_multipart_report(client):
    # 根节点自身就是 multipart/report（作用域路径为 ""）
    body = dsn_status_body(ENVELOPE, FAILED_RCPT)
    raw = (
        b"Subject: bounce\r\n"
        b"Content-Type: multipart/report;"
        b" report-type=delivery-status; boundary=RPT\r\n\r\n"
        + make_multipart([human_part(), dsn_part(body)], "RPT")
    )
    mid = post(client, raw)
    report = delivery(client, mid)["reports"][0]
    assert report["scope_node_path"] == ""
    assert report["report_node_path"] == "2"


def test_optional_envelope_fields_null(client):
    body = dsn_status_body(None, FAILED_RCPT)
    mid = post(client, message_with_parts(report_container(body)))
    env = delivery(client, mid)["reports"][0]["envelope"]
    assert env == {
        "original_envelope_id": None,
        "reporting_mta": "dns; mr.example.com",
        "received_from_mta": None,
        "arrival_date": None,
    }


# ---------------------------------------------------------------------------
# 作用域识别
# ---------------------------------------------------------------------------


def test_no_report_returns_empty_list(client):
    # 普通 mixed 邮件，没有 multipart/report
    plain = (
        b"Content-Type: text/plain; charset=utf-8\r\n\r\njust a body\r\n"
    )
    mid = post(client, message_with_parts(plain))
    data = delivery(client, mid)
    assert data["reports"] == []


def test_non_delivery_report_type_ignored(client):
    # multipart/report 但 report-type 不是 delivery-status（MDN）
    body = dsn_status_body(ENVELOPE, FAILED_RCPT)
    container = report_container(body, report_type="disposition-notification")
    mid = post(client, message_with_parts(container))
    assert delivery(client, mid)["reports"] == []


def test_report_type_case_insensitive(client):
    body = dsn_status_body(ENVELOPE, FAILED_RCPT)
    container = report_container(body, report_type="Delivery-Status")
    mid = post(client, message_with_parts(container))
    reports = delivery(client, mid)["reports"]
    assert len(reports) == 1
    assert reports[0]["scope_node_path"] == "1"


def test_status_nested_in_inner_multipart_is_not_direct_child(client):
    # multipart/report 的直接子件中没有 message/delivery-status：
    # 状态件被包在一层 multipart/mixed 里 → 422（缺少直接状态子件）。
    inner_mixed = (
        b"Content-Type: multipart/mixed; boundary=IN\r\n\r\n"
        + make_multipart([dsn_part(dsn_status_body(ENVELOPE, FAILED_RCPT))],
                         "IN")
    )
    raw = (
        b"Subject: bounce\r\n"
        b"Content-Type: multipart/report;"
        b" report-type=delivery-status; boundary=RPT\r\n\r\n"
        + make_multipart([human_part(), inner_mixed], "RPT")
    )
    mid = post(client, raw)
    r = client.get(f"/messages/{mid}/delivery-report")
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "INVALID_DELIVERY_STATUS"
    assert err["node_path"] == ""


def test_multiple_scopes_in_document_order(client):
    # 外层 mixed 含两个独立的 multipart/report 作用域（"2" 与 "3"）
    body1 = dsn_status_body(
        None,
        [("Final-Recipient", "rfc822; first@x.org"),
         ("Action", "failed"), ("Status", "5.1.1")],
    )
    body2 = dsn_status_body(
        None,
        [("Final-Recipient", "rfc822; second@x.org"),
         ("Action", "delivered"), ("Status", "2.0.0")],
    )
    plain = b"Content-Type: text/plain\r\n\r\nintro\r\n"
    mid = post(client, message_with_parts(
        plain, report_container(body1, boundary="R1"),
        report_container(body2, boundary="R2")))
    reports = delivery(client, mid)["reports"]
    assert [r["scope_node_path"] for r in reports] == ["2", "3"]
    assert reports[0]["recipients"][0]["final_recipient"] == "first@x.org"
    assert reports[1]["recipients"][0]["final_recipient"] == "second@x.org"


def test_status_inside_encapsulated_message_is_separate_scope(client):
    # multipart/report 出现在 message/rfc822 封装件内部：
    # 按整棵归档树（含封装报文内部）识别为独立作用域。
    body = dsn_status_body(None, FAILED_RCPT)
    inner_report = report_container(body, boundary="RPT")
    encapsulated = (
        b"Content-Type: message/rfc822\r\n\r\n"
        b"Subject: forwarded bounce\r\n"
        + inner_report
    )
    mid = post(client, message_with_parts(
        human_part("forwarded"), encapsulated))
    reports = delivery(client, mid)["reports"]
    assert len(reports) == 1
    # 根 "" → 子件 2（message/rfc822）→ 其内部 1（report）...
    assert reports[0]["scope_node_path"] == "2/1"
    assert reports[0]["report_node_path"] == "2/1/2"


# ---------------------------------------------------------------------------
# 422：结构与必填字段非法
# ---------------------------------------------------------------------------


def _post_report_and_get_error(client, body: bytes):
    mid = post(client, message_with_parts(report_container(body)))
    r = client.get(f"/messages/{mid}/delivery-report")
    assert r.status_code == 422, r.text
    return r.json()["error"]


def test_error_multiple_direct_status_parts(client):
    body = dsn_status_body(ENVELOPE, FAILED_RCPT)
    container = report_container(
        body,
        boundary="RPT",
        extra_parts=[dsn_part(body, ctype="message/delivery-status")],
    )
    # human(1) + status(2) + status(3)
    mid = post(client, message_with_parts(container))
    r = client.get(f"/messages/{mid}/delivery-report")
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "DUPLICATE_DELIVERY_STATUS"
    assert err["node_path"] == "1"
    assert err["detail"]["status_node_paths"] == ["1/2", "1/3"]


def test_error_missing_direct_status_part(client):
    # report-type=delivery-status 但直接子件里没有状态件
    raw = (
        b"Subject: bounce\r\n"
        b"Content-Type: multipart/report;"
        b" report-type=delivery-status; boundary=RPT\r\n\r\n"
        + make_multipart([human_part(), human_part("second")], "RPT")
    )
    mid = post(client, raw)
    r = client.get(f"/messages/{mid}/delivery-report")
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "INVALID_DELIVERY_STATUS"
    assert err["node_path"] == ""


def test_error_bad_status_code(client):
    body = dsn_status_body(
        None,
        [("Final-Recipient", "rfc822; b@x.org"),
         ("Action", "failed"), ("Status", "5.1")],
    )
    err = _post_report_and_get_error(client, body)
    assert err["code"] == "INVALID_DELIVERY_STATUS"
    assert err["node_path"] == "1/2"
    assert err["detail"]["field"] == "status"


def test_error_status_non_numeric(client):
    body = dsn_status_body(
        None,
        [("Final-Recipient", "rfc822; b@x.org"),
         ("Action", "failed"), ("Status", "5.x.1")],
    )
    err = _post_report_and_get_error(client, body)
    assert err["detail"]["field"] == "status"


def test_error_bad_action(client):
    body = dsn_status_body(
        None,
        [("Final-Recipient", "rfc822; b@x.org"),
         ("Action", "bounced"), ("Status", "5.1.1")],
    )
    err = _post_report_and_get_error(client, body)
    assert err["code"] == "INVALID_DELIVERY_STATUS"
    assert err["detail"]["field"] == "action"


def test_error_missing_required_fields(client):
    body = dsn_status_body(
        None,
        [("Final-Recipient", "rfc822; b@x.org"),
         ("Remote-MTA", "dns; mx.x.org")],
    )
    err = _post_report_and_get_error(client, body)
    assert err["detail"]["missing"] == ["action", "status"]


def test_error_final_recipient_not_typed(client):
    body = dsn_status_body(
        None,
        [("Final-Recipient", "b@x.org"),
         ("Action", "failed"), ("Status", "5.1.1")],
    )
    err = _post_report_and_get_error(client, body)
    assert err["detail"]["field"] == "final-recipient"


def test_error_empty_status_body(client):
    err = _post_report_and_get_error(client, b"")
    assert err["code"] == "INVALID_DELIVERY_STATUS"
    assert err["node_path"] == "1/2"


def test_error_no_recipient_blocks(client):
    err = _post_report_and_get_error(client, b"Reporting-MTA: dns; mr\r\n")
    assert err["code"] == "INVALID_DELIVERY_STATUS"


def test_error_malformed_field_line(client):
    body = (
        b"Reporting-MTA: dns; mr\r\n"
        b"\r\n"
        b"Final-Recipient: rfc822; b@x.org\r\n"
        b"Action failed\r\n"
        b"Status: 5.1.1\r\n"
    )
    err = _post_report_and_get_error(client, body)
    assert err["code"] == "INVALID_DELIVERY_STATUS"


def test_error_duplicate_field_in_block(client):
    body = (
        b"Reporting-MTA: dns; mr\r\n"
        b"\r\n"
        b"Final-Recipient: rfc822; b@x.org\r\n"
        b"Action: failed\r\n"
        b"Action: delayed\r\n"
        b"Status: 5.1.1\r\n"
    )
    err = _post_report_and_get_error(client, body)
    assert err["code"] == "INVALID_DELIVERY_STATUS"
    assert err["detail"]["field"] == "action"


def test_error_in_second_recipient_block_points_to_status_node(client):
    good = FAILED_RCPT
    bad = [
        ("Final-Recipient", "rfc822; c@x.org"),
        ("Action", "failed"),
        ("Status", "9.9"),
    ]
    err = _post_report_and_get_error(client, dsn_status_body(None, good, bad))
    assert err["node_path"] == "1/2"
    assert err["detail"]["block"] == 2
    assert err["detail"]["field"] == "status"


# ---------------------------------------------------------------------------
# 404 与只读
# ---------------------------------------------------------------------------


def test_message_404(client):
    assert client.get("/messages/999/delivery-report").status_code == 404


def test_report_is_read_only(client):
    body = dsn_status_body(ENVELOPE, FAILED_RCPT)
    mid = post(client, message_with_parts(report_container(body)))

    before = client.get(f"/messages/{mid}/nodes").json()
    # 先正常请求，再故意触发 422（坏作用域邮件不影响本邮件）
    assert delivery(client, mid)["reports"][0]["recipients"]
    bad_body = dsn_status_body(
        None,
        [("Final-Recipient", "rfc822; b@x.org"),
         ("Action", "failed"), ("Status", "bad")],
    )
    bad_mid = post(client, message_with_parts(report_container(bad_body)))
    assert client.get(f"/messages/{bad_mid}/delivery-report").status_code == 422

    after = client.get(f"/messages/{mid}/nodes").json()
    assert before == after
    # 归档总量不变（422 是查询期错误，本来就不写入）
    assert client.get("/messages").json()["total"] == 2
