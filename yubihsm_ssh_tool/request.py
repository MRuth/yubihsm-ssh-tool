from __future__ import absolute_import, division

import os
import struct
import base64
from cryptography.utils import int_to_bytes

CERT_TYPE = 1  # 1 = user, 2 = host
CA_KEY_TYPE = b'ssh-rsa'

DEFAULT_EXTENSIONS = {
    'permit-X11-forwarding' : None,
    'permit-agent-forwarding' : None,
    'permit-port-forwarding' : None,
    'permit-pty' : None,
    'permit-user-rc' : None
}


def create_request(ca_public_key, user_public_key_type, user_public_key, key_id,
                   principals, options, not_before, not_after, serial):

    cert_name = (user_public_key_type + '-cert-v01@openssh.com').encode('utf8')
    req = b''

    req += struct.pack('!I', len(cert_name)) + cert_name

    nonce = os.urandom(32)
    req += struct.pack('!I', len(nonce)) + nonce

    user_public_key_decoded = base64.b64decode(user_public_key)
    bytes_to_skip = struct.calcsize('!I') + (struct.unpack_from('!I',user_public_key_decoded)[0])
    req += (user_public_key_decoded[bytes_to_skip:])

    req += struct.pack('!Q', serial)

    req += struct.pack('!I', CERT_TYPE)

    key_id = key_id.encode('utf8')
    req += struct.pack('!I', len(key_id)) + key_id

    # for each principal print principals
    # starting with the total length of principal+length pairs
    n_principals = len(principals)
    total_principals_length = sum(len(s) for s in principals)

    req += struct.pack('!I', (n_principals * 4) + total_principals_length)

    for s in principals:
        s = s.encode('utf8')
        req += struct.pack('!I', len(s)) + s

    req += struct.pack('!Q', not_after)

    req += struct.pack('!Q', not_before)

    CRITICAL_OPTIONS_DICT = {}
    EXTENSIONS_DICT = DEFAULT_EXTENSIONS.copy()

    #parse options provided
    if options is not None:
        for opt in options:
            name, _, data = opt.partition('=')

            #If option is clear, clear both Critical Options and Extensions
            if name.lower() == 'clear':
                CRITICAL_OPTIONS_DICT.clear()
                EXTENSIONS_DICT.clear()

            elif name.lower().startswith('no-'):
                CRITICAL_OPTIONS_DICT = {k:v for k,v in CRITICAL_OPTIONS_DICT.items() if name[3:] not in k}
                EXTENSIONS_DICT = {k:v for k,v in EXTENSIONS_DICT.items() if name[3:] not in k}
            else:
                data = data if data != '' else None
                
                #Critical Options
                if ((name == 'force-command') or (name == 'source-address')) and (data is not None):
                    CRITICAL_OPTIONS_DICT[name] = data
                #Other Extensions
                else:
                    EXTENSIONS_DICT[name] = data

    CRITICAL_OPTIONS = b''
    EXTENSIONS = b''

    for key in sorted(CRITICAL_OPTIONS_DICT):
        value = ('' if CRITICAL_OPTIONS_DICT[key] is None else CRITICAL_OPTIONS_DICT[key])
        
        CRITICAL_OPTIONS += (
            struct.pack('!I',len(key)) + key.encode('utf8') +
            ( struct.pack('!I',(struct.calcsize('!I')+len(value))) if len(value) > 0 else b'') + 
            struct.pack('!I',len(value)) + value.encode('utf8')
        )

    for key in sorted(EXTENSIONS_DICT):
        value = ('' if EXTENSIONS_DICT[key] is None else EXTENSIONS_DICT[key])

        EXTENSIONS += (
            struct.pack('!I',len(key)) + key.encode('utf8') + 
            ( struct.pack('!I',(struct.calcsize('!I')+len(value))) if len(value) > 0 else b'') + 
            struct.pack('!I',len(value)) + value.encode('utf8')
        )
    
    req += struct.pack('!I',len(CRITICAL_OPTIONS)) + CRITICAL_OPTIONS

    req += struct.pack('!I', len(EXTENSIONS)) + EXTENSIONS

    req += struct.pack('!I', 0)  # NOTE(adma): RFU

    req += struct.pack('!I',len(ca_public_key)) + ca_public_key

    return req
