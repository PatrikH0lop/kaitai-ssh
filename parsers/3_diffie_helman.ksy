meta:
  id: diffie_helman
  file-extension: diffie_helman

seq:
  - id: packet_length
    size: 4
  - id: padding_length
    size: 1
  - id: message_code
    size: 1
  - id: multi_precision_length
    size: 4
  - id: dh_client
    size: 32
  - id: padding
    size: 6