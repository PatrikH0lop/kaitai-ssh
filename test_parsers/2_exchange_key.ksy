meta:
  id: client_exchange_key_init
  file-extension: client_exchange_key_init
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
      - id: message_number
        type: u1
        enum: message_numbers
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

  algorithm_list:
    seq:
      - id: algorithm
        type: str
        encoding: utf-8
        terminator: 0x2c
        eos-error: false
        repeat: eos

enums:
  message_numbers:
    1: ssh_msg_disconnect
    2: ssh_msg_ignore
    3: ssh_msg_unimplemented
    4: ssh_msg_debug
    5: ssh_msg_service_request
    6: ssh_msg_service_accept
    20: ssh_msg_kexinit
    21: ssh_msg_newkeys