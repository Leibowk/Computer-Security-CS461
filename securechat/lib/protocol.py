'''
This is a packet structure
'''

PACKETS = {
    None: 0,

    "EXIT": 1,
    "FULL": 2,
    "ACCEPT": 3,
    "USERNAME-ACCEPT": 4,
    "USERNAME-TAKEN": 5,
    "USERNAME-INVALID": 6,
    "ERROR": 7,

    "HELLO": 8,
    "KEY-EXCHANGE": 9,
    "CERTIFICATE-EXCHANGE": 10,
    "REQUEST-USERNAME": 11,

    "DH-HELLO": 12,
    "DH-KEY-EXCHANGE": 13,
    "DH-REPLY": 14,
    
    "P2P-HELLO": 15,
    "P2P-KEY-EXCHANGE": 16,
    "P2P-REPLY": 17,

    "NO-CERTIFICATE": 18
}
