#!/usr/bin/env python3
"""Broker Upload CI sidecar.

Stdlib-only by design. The composite action installs/selects Python 3.14 and
then delegates artifact upload grant, presigned PUT, and publication register
logic to this script.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import sys
import tempfile
import time
from typing import Any
from urllib import error, parse, request

MIN_PYTHON = (3, 14)
JSON_CONTENT_TYPE = "application/json"
DEFAULT_CONTENT_TYPE = "application/octet-stream"
ZSTD_CONTENT_TYPE = "application/zstd"
BROKER_TIMEOUT_SECONDS = 60
UPLOAD_TIMEOUT_SECONDS = 300
CONNECT_RETRY_ATTEMPTS = 3
RETRY_SLEEP_SECONDS = 1.0
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class BrokerUploadError(Exception):
    pass


class HttpResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text())


def fail(message: str, *, exit_code: int = 1) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(exit_code)


def mask(value: str | None) -> None:
    if value and "\n" not in value and "\r" not in value:
        print(f"::add-mask::{value}")


def get_env(name: str, *, required: bool = True, default: str = "") -> str:
    value = os.environ.get(name, default)
    if required and not value:
        fail(f"{name} is required")
    return value


def reject_header_value(name: str, value: str) -> None:
    if "\r" in value or "\n" in value:
        fail(f"{name} must not contain CR/LF")


def reject_header_name(name: str) -> None:
    if not HEADER_NAME_RE.fullmatch(name):
        fail(f"Invalid HTTP header name: {name!r}")


def ensure_python_version() -> None:
    if sys.version_info < MIN_PYTHON:
        fail(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; "
            f"current={sys.version.split()[0]}"
        )


def validate_https_broker_url(raw_url: str) -> str:
    reject_header_value("BROKER_URL", raw_url)
    parsed = parse.urlparse(raw_url)
    if parsed.scheme != "https" or not parsed.netloc:
        fail("broker_url must be an https URL")
    if any(ch.isspace() for ch in raw_url):
        fail("broker_url must not contain whitespace")
    return raw_url.rstrip("/")


def validate_http_url(raw_url: str, *, label: str) -> None:
    parsed = parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        fail(f"{label} must be an http(s) URL")
    if any(ch.isspace() for ch in raw_url):
        fail(f"{label} must not contain whitespace")


def load_json_file(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fp:
            return json.load(fp)
    except FileNotFoundError:
        fail(f"Artifact manifest file not found: {path}")
    except json.JSONDecodeError as exc:
        fail(f"Artifact manifest is not valid JSON: {path}: {exc}")


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_under_workspace(path_text: str, workspace: Path) -> Path:
    p = Path(path_text)
    if not p.is_absolute():
        p = workspace / p
    return p.resolve()


def is_path_under(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([str(path), str(root)]) == str(root)
    except ValueError:
        return False


def parse_bool_env(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False
    fail(f"{name} must be a boolean: true/false")


def parse_zstd_level(raw: str) -> int:
    try:
        level = int(raw)
    except ValueError:
        fail("compression_level must be an integer")

    try:
        from compression import zstd
    except Exception as exc:
        fail(f"Python 3.14 compression.zstd module is required for zstd compression: {exc}")

    lower, upper = zstd.CompressionParameter.compression_level.bounds()
    if not (lower <= level <= upper):
        fail(f"compression_level must be between {lower} and {upper}; got {level}")
    return level


def compressed_filename(filename: str) -> str:
    if filename.endswith(".zst"):
        return filename
    return f"{filename}.zst"


def zstd_compress_file(source: Path, destination: Path, *, level: int) -> None:
    try:
        from compression import zstd
    except Exception as exc:
        fail(f"Python 3.14 compression.zstd module is required for zstd compression: {exc}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("wb") as raw_dst:
        with zstd.open(raw_dst, "wb", level=level) as zst_dst:
            shutil.copyfileobj(src, zst_dst, length=1024 * 1024)


def prepare_upload_file(
    *,
    filename: str,
    local_path: Path,
    content_type: str,
    compress_uploads: bool,
    compression_level: int,
    tmp_dir: Path,
    idx: int,
) -> dict[str, str]:
    original_size = local_path.stat().st_size
    original_sha256 = sha256_file(local_path)

    if not compress_uploads:
        return {
            "filename": filename,
            "path": str(local_path),
            "content_type": content_type,
            "sha256": original_sha256,
            "original_filename": filename,
            "original_path": str(local_path),
            "original_sha256": original_sha256,
            "original_size": str(original_size),
            "compression": "none",
        }

    upload_filename = compressed_filename(filename)
    compressed_path = tmp_dir / "compressed" / f"{idx:05d}-{upload_filename.replace('/', '_')}"
    zstd_compress_file(local_path, compressed_path, level=compression_level)
    compressed_size = compressed_path.stat().st_size
    compressed_sha256 = sha256_file(compressed_path)

    print(
        "compressed_artifact "
        f"filename={filename} upload_filename={upload_filename} "
        f"original_bytes={original_size} compressed_bytes={compressed_size} "
        f"level={compression_level}",
        file=sys.stderr,
    )

    return {
        "filename": upload_filename,
        "path": str(compressed_path),
        "content_type": ZSTD_CONTENT_TYPE,
        "sha256": compressed_sha256,
        "original_filename": filename,
        "original_path": str(local_path),
        "original_sha256": original_sha256,
        "original_size": str(original_size),
        "compressed_size": str(compressed_size),
        "compression": "zstd",
        "compression_level": str(compression_level),
    }


def normalize_manifest(
    manifest_path: Path,
    artifact_root: str,
    workspace: Path,
    *,
    compress_uploads: bool,
    compression_level: int,
    tmp_dir: Path,
) -> list[dict[str, str]]:
    manifest_value = load_json_file(manifest_path)
    if not isinstance(manifest_value, list) or not manifest_value:
        fail("files manifest must be a non-empty array")

    root_path = Path(artifact_root)
    if not root_path.is_absolute():
        root_path = workspace / root_path
    root_path = root_path.resolve()
    if not root_path.is_dir():
        fail(f"artifact_root directory not found: {artifact_root}")

    seen_upload_filenames: set[str] = set()
    enriched: list[dict[str, str]] = []

    for idx, entry in enumerate(manifest_value):
        if not isinstance(entry, dict):
            fail(f"manifest entry #{idx} must be an object")

        filename = entry.get("filename")
        local_path_text = entry.get("path")
        content_type = entry.get("content_type", DEFAULT_CONTENT_TYPE)

        if not isinstance(filename, str) or not filename:
            fail(f"manifest entry #{idx} must include non-empty string field: filename")
        if not isinstance(local_path_text, str) or not local_path_text:
            fail(f"manifest entry #{idx} must include non-empty string field: path")
        if not isinstance(content_type, str) or not content_type:
            fail(f"manifest entry #{idx} content_type must be a non-empty string")

        reject_header_value("content_type", content_type)

        local_path = resolve_under_workspace(local_path_text, workspace)
        if not local_path.is_file():
            fail(f"Artifact file not found: {local_path_text}")
        if not is_path_under(local_path, root_path):
            fail(f"Artifact path is outside allowed artifact_root: {local_path_text}")

        upload_entry = prepare_upload_file(
            filename=filename,
            local_path=local_path,
            content_type=content_type,
            compress_uploads=compress_uploads,
            compression_level=compression_level,
            tmp_dir=tmp_dir,
            idx=idx,
        )
        upload_filename = upload_entry["filename"]
        if upload_filename in seen_upload_filenames:
            fail(f"files manifest contains duplicate upload filename: {upload_filename}")
        seen_upload_filenames.add(upload_filename)
        enriched.append(upload_entry)

    return enriched


def parse_cf_access_headers() -> dict[str, str]:
    client_id = os.environ.get("CF_ACCESS_CLIENT_ID", "")
    client_secret = os.environ.get("CF_ACCESS_CLIENT_SECRET", "")

    if bool(client_id) != bool(client_secret):
        fail("cf_access_client_id and cf_access_client_secret must be provided together")

    if not client_id and not client_secret:
        return {}

    reject_header_value("CF_ACCESS_CLIENT_ID", client_id)
    reject_header_value("CF_ACCESS_CLIENT_SECRET", client_secret)
    mask(client_id)
    mask(client_secret)

    return {
        "CF-Access-Client-Id": client_id,
        "CF-Access-Client-Secret": client_secret,
    }


def broker_headers(user_agent: str, cf_headers: dict[str, str]) -> dict[str, str]:
    reject_header_value("BROKER_USER_AGENT", user_agent)
    headers = {
        "Content-Type": JSON_CONTENT_TYPE,
        "Accept": JSON_CONTENT_TYPE,
        "User-Agent": user_agent,
    }
    headers.update(cf_headers)
    return headers


def read_http_error(exc: error.HTTPError) -> HttpResponse:
    body = exc.read() or b""
    headers = {k: v for k, v in exc.headers.items()}
    return HttpResponse(exc.code, headers, body)


def http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: bytes | Any | None = None,
    timeout: int = BROKER_TIMEOUT_SECONDS,
    expected_statuses: set[int] | None = None,
    retry: bool = True,
) -> HttpResponse:
    headers = headers or {}
    expected_statuses = expected_statuses or {200}
    last_response: HttpResponse | None = None
    last_error: Exception | None = None

    attempts = CONNECT_RETRY_ATTEMPTS if retry else 1
    for attempt in range(1, attempts + 1):
        req = request.Request(url=url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
                body = resp.read() or b""
                response = HttpResponse(resp.status, {k: v for k, v in resp.headers.items()}, body)
        except error.HTTPError as exc:
            response = read_http_error(exc)
        except error.URLError as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(RETRY_SLEEP_SECONDS)
                continue
            raise BrokerUploadError(f"HTTP request failed: {method} {safe_url_label(url)}: {exc}") from exc

        if response.status in expected_statuses:
            return response

        last_response = response
        if not retry or response.status not in {408, 429, 500, 502, 503, 504} or attempt >= attempts:
            return response

        time.sleep(RETRY_SLEEP_SECONDS)

    if last_response is not None:
        return last_response
    raise BrokerUploadError(f"HTTP request failed: {method} {safe_url_label(url)}: {last_error}")


def http_json_post(url: str, payload: dict[str, Any], headers: dict[str, str]) -> HttpResponse:
    return http_request(
        "POST",
        url,
        headers=headers,
        data=compact_json(payload).encode("utf-8"),
        timeout=BROKER_TIMEOUT_SECONDS,
        expected_statuses={200},
        retry=True,
    )


def try_parse_json_body(response: HttpResponse) -> Any | None:
    try:
        return response.json()
    except Exception:
        return None


def print_response_error(response: HttpResponse, *, prefix: str, fallback: str) -> None:
    print(f"{prefix}_status={response.status}", file=sys.stderr)
    body_json = try_parse_json_body(response)
    if isinstance(body_json, dict):
        for key in ("error", "message"):
            value = body_json.get(key)
            if value:
                print(str(value), file=sys.stderr)
        if "details" in body_json:
            print(compact_json(body_json["details"]), file=sys.stderr)
        if response.status == 500:
            print("Broker returned 500. The request reached broker; inspect broker logs with the same run context.", file=sys.stderr)
        elif response.status in {401, 403}:
            print("Authentication or edge policy denied the request. Check session_id and Cloudflare Access headers.", file=sys.stderr)
        elif response.status == 429:
            print("Request was rate-limited by broker or edge policy.", file=sys.stderr)
        return

    print(fallback, file=sys.stderr)
    body = response.text().strip()
    if body:
        print(body[:4096], file=sys.stderr)
    if response.status in {401, 403} and ("cloudflare" in body.lower() or "1020" in body):
        print("Response looks like a Cloudflare/WAF/Access denial before broker handled the request.", file=sys.stderr)


def safe_url_label(url: str) -> str:
    parsed = parse.urlparse(url)
    if parsed.scheme and parsed.netloc:
        return parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    return url


def expect_json_object(response: HttpResponse, *, context: str) -> dict[str, Any]:
    value = try_parse_json_body(response)
    if not isinstance(value, dict):
        print_response_error(
            response,
            prefix="broker",
            fallback=f"{context} returned a non-JSON response",
        )
        raise SystemExit(1)
    return value


def request_upload_grant(
    broker_url: str,
    headers: dict[str, str],
    *,
    session_id: str,
    project: str,
    ecosystem: str,
    channel: str,
    version: str,
    files: list[dict[str, str]],
) -> dict[str, Any]:
    payload = {
        "session_id": session_id,
        "project": project,
        "ecosystem": ecosystem,
        "channel": channel,
        "version": version,
        "files": [{"filename": f["filename"], "sha256": f["sha256"]} for f in files],
    }
    response = http_json_post(f"{broker_url}/v1/grants/artifact-upload", payload, headers)
    if response.status != 200:
        print_response_error(
            response,
            prefix="broker",
            fallback="artifact upload grant request failed with a non-JSON response",
        )
        raise SystemExit(1)

    data = expect_json_object(response, context="artifact upload grant request")
    validate_upload_grant_response(data)
    return data


def validate_upload_grant_response(data: dict[str, Any]) -> None:
    grant_id = data.get("grant_id")
    uploads = data.get("uploads")
    if not isinstance(grant_id, str) or not grant_id:
        fail("Broker upload grant returned invalid grant_id")
    if not isinstance(uploads, list):
        fail("Broker upload grant returned invalid uploads list")
    filenames: list[str] = []
    for idx, item in enumerate(uploads):
        if not isinstance(item, dict):
            fail(f"Broker uploads[{idx}] must be an object")
        filename = item.get("filename")
        url = item.get("url")
        method = item.get("method")
        storage_key = item.get("storage_key")
        if not isinstance(filename, str) or not filename:
            fail(f"Broker uploads[{idx}] has invalid filename")
        if not isinstance(url, str) or not url:
            fail(f"Broker uploads[{idx}] has invalid url")
        if not isinstance(method, str) or method.upper() != "PUT":
            fail(f"Broker uploads[{idx}] has unsupported method: {method}")
        if not isinstance(storage_key, str) or not storage_key:
            fail(f"Broker uploads[{idx}] has invalid storage_key")
        validate_http_url(url, label=f"Upload URL for {filename}")
        filenames.append(filename)
        mask(url)
    if len(filenames) != len(set(filenames)):
        fail("Broker upload grant returned duplicate upload filenames")


def merge_header(headers: dict[str, str], key: str, value: str) -> None:
    reject_header_name(key)
    reject_header_value(key, value)
    existing = [k for k in headers if k.lower() == key.lower()]
    for k in existing:
        del headers[k]
    headers[key] = value


def upload_one_file(upload: dict[str, Any], local: dict[str, str]) -> None:
    filename = upload["filename"]
    upload_url = upload["url"]
    method = str(upload.get("method", "PUT")).upper()
    remote_headers = upload.get("headers") or {}
    if not isinstance(remote_headers, dict):
        fail(f"Upload headers must be an object for {filename}")

    headers: dict[str, str] = {}
    merge_header(headers, "Content-Type", local["content_type"])
    size = Path(local["path"]).stat().st_size
    merge_header(headers, "Content-Length", str(size))

    for key, value in remote_headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            fail(f"Upload header entries must be string pairs for {filename}")
        merge_header(headers, key, value)

    path = Path(local["path"])
    response: HttpResponse | None = None
    last_error: Exception | None = None

    for attempt in range(1, CONNECT_RETRY_ATTEMPTS + 1):
        try:
            with path.open("rb") as fp:
                response = http_request(
                    method,
                    upload_url,
                    headers=headers,
                    data=fp,
                    timeout=UPLOAD_TIMEOUT_SECONDS,
                    expected_statuses={200, 201, 204},
                    retry=False,
                )
        except BrokerUploadError as exc:
            last_error = exc
            if attempt < CONNECT_RETRY_ATTEMPTS:
                time.sleep(RETRY_SLEEP_SECONDS)
                continue
            raise

        if response.status in {200, 201, 204}:
            return
        if response.status not in {408, 429, 500, 502, 503, 504} or attempt >= CONNECT_RETRY_ATTEMPTS:
            break
        time.sleep(RETRY_SLEEP_SECONDS)

    if response is None:
        raise BrokerUploadError(f"Artifact upload failed for {filename}: {last_error}")

    print(f"artifact_upload_status={response.status}", file=sys.stderr)
    print(f"Artifact upload failed for {filename}", file=sys.stderr)
    print(f"artifact_upload_sha256={local['sha256']}", file=sys.stderr)
    body_json = try_parse_json_body(response)
    if body_json is not None:
        print(compact_json(body_json), file=sys.stderr)
    else:
        text = response.text().strip()
        if text:
            print(text[:4096], file=sys.stderr)
    raise SystemExit(1)


def upload_files(grant: dict[str, Any], enriched: list[dict[str, str]]) -> None:
    uploads = grant["uploads"]
    if len(uploads) != len(enriched):
        fail(f"Upload count mismatch: local={len(enriched)}, remote={len(uploads)}")

    locals_by_filename = {item["filename"]: item for item in enriched}
    for upload in uploads:
        filename = upload["filename"]
        local = locals_by_filename.get(filename)
        if local is None:
            fail(f"Expected exactly one local manifest entry for {filename}")
        upload_one_file(upload, local)


def register_publication(
    broker_url: str,
    headers: dict[str, str],
    *,
    grant: dict[str, Any],
    project: str,
    ecosystem: str,
    channel: str,
    version: str,
    enriched: list[dict[str, str]],
) -> dict[str, Any]:
    uploads_by_filename = {item["filename"]: item for item in grant["uploads"]}
    files: list[dict[str, str]] = []
    for local in enriched:
        remote = uploads_by_filename.get(local["filename"])
        if remote is None:
            fail(f"Register payload missing remote upload entry for {local['filename']}")
        files.append(
            {
                "filename": local["filename"],
                "storage_key": remote["storage_key"],
                "sha256": local["sha256"],
            }
        )

    if len(files) != len(enriched):
        fail(f"Register payload file count mismatch: local={len(enriched)}, register={len(files)}")

    payload = {
        "grant_id": grant["grant_id"],
        "project": project,
        "ecosystem": ecosystem,
        "channel": channel,
        "version": version,
        "files": files,
    }

    response = http_json_post(f"{broker_url}/v1/artifacts/register", payload, headers)
    if response.status != 200:
        print_response_error(
            response,
            prefix="broker",
            fallback="artifact register request failed with a non-JSON response",
        )
        raise SystemExit(1)

    data = expect_json_object(response, context="artifact register request")
    if not isinstance(data.get("publication_id"), str) or not data.get("publication_id"):
        fail("Broker register response returned invalid publication_id")
    if not isinstance(data.get("status"), str) or not data.get("status"):
        fail("Broker register response returned invalid status")
    return data


def write_github_output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        print(f"{name}={value}")
        return

    with open(output_path, "a", encoding="utf-8") as fp:
        if "\n" in value or "\r" in value:
            delimiter = f"BROKER_UPLOAD_{hashlib.sha256(name.encode()).hexdigest()[:12]}"
            fp.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            fp.write(f"{name}={value}\n")


def main() -> int:
    ensure_python_version()

    workspace = Path(get_env("GITHUB_WORKSPACE", required=False, default=os.getcwd())).resolve()
    broker_url = validate_https_broker_url(get_env("BROKER_URL"))
    project = get_env("PROJECT")
    session_id = get_env("SESSION_ID")
    ecosystem = get_env("ECOSYSTEM")
    channel = get_env("CHANNEL")
    version = get_env("VERSION")
    user_agent = get_env("BROKER_USER_AGENT", required=False, default="auth-broker-x-ci/1.0")
    artifact_root = get_env("ARTIFACT_ROOT", required=False, default="dist")
    files_manifest_path = resolve_under_workspace(get_env("FILES_MANIFEST_PATH"), workspace)
    compress_uploads = parse_bool_env("COMPRESS_UPLOADS", default=False)
    compression_level = parse_zstd_level(get_env("COMPRESSION_LEVEL", required=False, default="3")) if compress_uploads else 0

    mask(session_id)

    cf_headers = parse_cf_access_headers()
    headers = broker_headers(user_agent, cf_headers)

    tmp_dir = Path(tempfile.mkdtemp(prefix="broker-upload.", dir=os.environ.get("RUNNER_TEMP") or None))
    try:
        enriched = normalize_manifest(
            files_manifest_path,
            artifact_root,
            workspace,
            compress_uploads=compress_uploads,
            compression_level=compression_level,
            tmp_dir=tmp_dir,
        )
        (tmp_dir / "broker-upload-enriched-manifest.json").write_text(compact_json(enriched), encoding="utf-8")

        grant = request_upload_grant(
            broker_url,
            headers,
            session_id=session_id,
            project=project,
            ecosystem=ecosystem,
            channel=channel,
            version=version,
            files=enriched,
        )
        (tmp_dir / "broker-upload-grant-body.json").write_text(compact_json(grant), encoding="utf-8")

        upload_files(grant, enriched)

        publication = register_publication(
            broker_url,
            headers,
            grant=grant,
            project=project,
            ecosystem=ecosystem,
            channel=channel,
            version=version,
            enriched=enriched,
        )
        (tmp_dir / "broker-upload-register-body.json").write_text(compact_json(publication), encoding="utf-8")

        write_github_output("upload_grant_id", grant["grant_id"])
        write_github_output("artifact_uploads_json", compact_json(grant["uploads"]))
        write_github_output("artifact_publication_id", publication["publication_id"])
        write_github_output("artifact_publication_status", publication["status"])
        return 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokerUploadError as exc:
        fail(str(exc))
