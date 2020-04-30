meta:
  id: client_exchange_key_init
  file-extension: client_exchange_key_init


seq:
  - id: packet_length
    size: 4
  - id: padding_length
    size: 1
  - id: message_code
    size: 1
  - id: cookie
    size: 16
  - id: kex_algorithms
    size: 4
  - id: kex_algorithms_string
    size: 337
  - id: server_host_key_length
    size: 4
  - id: dalsie
    size: 1017
  - id: padding_string
    size: 8