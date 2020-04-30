meta:
  id: diffie_helman
  file-extension: diffie_helman
  endian: be

instances:
  ssh_packet:
    type: ssh_packet

types:
  ssh_packet:
    seq:
      - id: packet_length
        type: u4
      - id: padding_length
        type: u1
      - id: payload
        type: payload
      - id: random_padding
        size-eos: true
  
  payload:
    seq:
      - id: message_code
        type: u1
        enum: message_numbers
      - id: multi_precision_integer_length
        type: u4
      - id: e
        size: multi_precision_integer_length

enums:
  message_numbers:
    30: ssh_msg_kexdh_init
    31: ssh_msg_kexdg_reply