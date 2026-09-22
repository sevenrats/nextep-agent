from enum import StrEnum


class AcmeProvider(StrEnum):
    LETSENCRYPT = "letsencrypt"
    INTERNAL = "internal"

class AcmeType(StrEnum):
    DNS = "dns"
    HTTP = "http"
    TLS_ALPN = "tls-alpn"
