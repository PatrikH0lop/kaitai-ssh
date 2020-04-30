meta:
  id: ssh_parser
  title: SSH protocol parser by Patrik Holop (xholop01).
  file-extension: bin
  endian: be
  ks-opaque-types: true
  xref: 4253
  encoding: UTF-8


doc: Parser of the SSH protocol in Kaitai.
doc-ref: https://tools.ietf.org/html/rfc4253


seq:
  # Type of the message, either ssh identification string
  # or SSH packet.
  - id: ssh_banner_or_packet_length
    type: b32
  - id: body
    type:
      switch-on: ssh_banner_or_packet_length
      cases:
        # '[0x53, 0x53, 0x48, 0x2d]' is SSH banner.
        0x5353482D: id_banner
        _: ssh_packet


types:
  # SSH identification string.
  id_banner:
    seq:
    - id: protoversion
      type: str
      encoding: utf-8
      terminator: 0x2d
    - id: additional_information
      terminator: 0x0a
      type: additional_ssh_banner_data

  additional_ssh_banner_data:
    seq:
      - id: softwareversion
        terminator: 0x20
        type: str
        encoding: utf-8
        eos-error: false
      - id: comment
        type: str
        encoding: utf-8
        terminator: 0x0a
        size-eos: true
      - id: last_char
        type: u1
        type: 0x0a

  # SSH packet.
  ssh_packet:
    seq:
      - id: padding_length
        type: u1
      - id: payload
        type: payload
      - id: random_paddin
        size-eos: true

  # Payload of the message.
  payload:
    seq:
      - id: message_number
        type: u1
        enum: message_numbers
      - id: payload_specific_type
        type:
          switch-on: message_number
          cases:
            'message_numbers::ssh_msg_kexinit': key_exchange_init
            'message_numbers::ssh_msg_newkeys': key_exchange_new_keys
            'message_numbers::ssh_msg_kexdh_init': diffie_helman_init
            'message_numbers::ssh_msg_kexdg_reply': diffie_helman_reply
            _: encrypted_data

  # Encrypted payload.
  encrypted_data:
    seq:
      - id: encrypted_message
        size: _root.ssh_banner_or_packet_length
      - id: mac
        size-eos: true

  # Payload for exchanging of keys: client init.
  key_exchange_init:
    seq:
      - id: cookie
        size: 16
      - id: kex_algorithms_length
        type: u4
      - id: kex_algorithms
        size: kex_algorithms_length
        type: algorithm_list
      - id: server_host_key_algorithms_length
        type: u4
      - id: server_host_key_algorithms
        type: algorithm_list
        size: server_host_key_algorithms_length
      - id: encryption_algorithms_client_to_server_length
        type: u4
      - id: encryption_algorithms_client_to_server
        type: algorithm_list
        size: encryption_algorithms_client_to_server_length
      - id: encryption_algorithms_server_to_client_length
        type: u4
      - id: encryption_algorithms_server_to_client
        type: algorithm_list
        size: encryption_algorithms_server_to_client_length
      - id: mac_algorithms_client_to_server_length
        type: u4
      - id: mac_algorithms_client_to_server
        type: algorithm_list
        size: mac_algorithms_client_to_server_length
      - id: mac_algorithms_server_to_client_length
        type: u4
      - id: mac_algorithms_server_to_client
        type: algorithm_list
        size: mac_algorithms_server_to_client_length
      - id: compression_algorithms_client_to_server_length
        type: u4
      - id: compression_algorithms_client_to_server
        type: algorithm_list
        size: compression_algorithms_client_to_server_length
      - id: compression_algorithms_server_to_client_length
        type: u4
      - id: compression_algorithms_server_to_client
        type: algorithm_list
        size: compression_algorithms_server_to_client_length
      - id: languages_client_to_server_length
        type: u4
      - id: languages_client_to_server
        type: algorithm_list
        size: languages_client_to_server_length
      - id: languages_server_to_client_length
        type: u4
      - id: languages_server_to_client
        type: algorithm_list
        size: languages_server_to_client_length
      - id: first_kex_packet_follows
        type: u1
      - id: reserved_for_future_extension
        type: u4
  
  # SSH message for exhanging new keys.
  key_exchange_new_keys:
    seq: []

  # Diffie helman algorithm init.
  diffie_helman_init:
    seq:
      - id: multi_precision_integer_length
        type: u4
      - id: e
        size: multi_precision_integer_length
  
  # Diffie helman algorithm reply.
  diffie_helman_reply:
    seq:
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

  # List of algorithms for key exchange.
  algorithm_list:
    seq:
      - id: algorithm
        type: str
        encoding: utf-8
        terminator: 0x2c
        eos-error: false
        repeat: eos

enums:
  # SSH message variants.
  message_numbers:
    1: ssh_msg_disconnect
    2: ssh_msg_ignore
    3: ssh_msg_unimplemented
    4: ssh_msg_debug
    5: ssh_msg_service_request
    6: ssh_msg_service_accept
    20: ssh_msg_kexinit
    21: ssh_msg_newkeys
    30: ssh_msg_kexdh_init
    31: ssh_msg_kexdg_reply

