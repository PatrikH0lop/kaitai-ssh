meta:
  id: encrypted_packet
  file-extension: encrypted_packet
  endian: be

instances:
  ssh_packet:
    type: ssh_packet

types:
  ssh_packet:
    seq:
      - id: packet_length
        type: u4
      - id: encrypted_message
        size: packet_length
      - id: mac
        size-eos: true
