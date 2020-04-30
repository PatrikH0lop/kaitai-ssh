meta:
  id: ssh_parser
  file-extension: ssh_parser
  endian: be
  ks-opaque-types: true


instances:
  identification:
    type: id_banner

types:
  id_banner:
    seq:
    - id: ssh
      type: str
      encoding: utf-8
      terminator: 0x2d
    - id: protoversion
      type: str
      encoding: utf-8
      terminator: 0x2d
    - id: additional_information
      terminator: 0x0a
      type: additional

  additional:
    seq:
      - id: softwareversion
        terminator: 0x20
        type: str
        encoding: utf-8
        eos-error: false
      - id: comment
        type: str
        encoding: utf-8
        size-eos: true
      - id: last_char
        type: u1