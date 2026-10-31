import ipaddress
import socket
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}


class UnsafeURL(ValueError):
    pass


def validate_url(url):
    if not url or len(url) > MAX_URL_LENGTH:
        raise UnsafeURL("URL kosong atau terlalu panjang (maks 2048 karakter).")

    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeURL("Hanya URL http:// atau https:// yang diizinkan.")

    host = parsed.hostname
    if not host:
        raise UnsafeURL("URL tidak memiliki nama host.")

    if host == "localhost" or host.endswith(".localhost"):
        raise UnsafeURL("Akses ke localhost tidak diizinkan.")

    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise UnsafeURL("Nama host tidak dapat di-resolve.")

    for info in addresses:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise UnsafeURL(
                f"Host mengarah ke alamat internal ({ip}); ditolak untuk mencegah SSRF."
            )

    return url
