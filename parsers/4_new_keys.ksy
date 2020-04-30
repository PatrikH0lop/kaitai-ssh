meta:
  id: diffie_helman_reply
  file-extension: diffie_helman_reply
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

enums:
  message_numbers:
    21: ssh_msg_newkeys