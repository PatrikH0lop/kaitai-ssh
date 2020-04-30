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
      - id: host_key_length
        type: u4
      - id: host_key_type_length
        type: u4
      - id: host_key_type
        size: host_key_type_length
        type: str
        encoding: utf-8
      - id: ecdsa_elliptic_curve_identifier_length
        type: u4
      - id: ecdsa_ellipitic_curve_identifier
        size: ecdsa_elliptic_curve_identifier_length
        type: str
        encoding: utf-8
      - id: ecdsa_public_key_length
        type: u4
      - id: ecdsa_public_key
        size: ecdsa_public_key_length
      - id: multi_precision_integer_length
        type: u4
      - id: f
        size: multi_precision_integer_length
      - id: signature_of_h_length
        type: u4
      - id: signature_of_h
        size: signature_of_h_length
enums:
  message_numbers:
    30: ssh_msg_kexdh_init
    31: ssh_msg_kexdg_reply