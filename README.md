## Kaitai SSH parser

#### Description
The goal of this project is to create a parser of SSH protocol messages using Kaitai.<br>
**Author**: Patrik Holop (xholop01)

#### Documentation and references

##### SSH protocol
Structure of SSH protocol messages is described in [RFC 4253](https://tools.ietf.org/html/rfc4253).<br>
More precise documentation for SSH ranges from [RFC 4250](https://tools.ietf.org/html/rfc4250) to [RFC 4256](https://tools.ietf.org/html/rfc4256).<br>
Another used resources was an [overview of SSH structure for traffic analysis](https://www.trisul.org/blog/traffic-analysis-of-secure-shell-ssh/).

##### Kaitai

[Kaitai Struct User Guide](https://doc.kaitai.io/user_guide.html)<br>
[KSY Style Guide](https://doc.kaitai.io/ksy_style_guide.html)

##### Versions

This project is able to parse protocol messages for SSHv2.<br>
*Based on RFC: "Earlier versions of this protocol have not been formally documented."* This means that we would be unable to create a formal parser for previous versions.

#### Parser

*Disclaimer: Examples provided by official pages of Kaitai Struct do not contain direct examples of SSH protocol except parsing of [SSH public keys](https://formats.kaitai.io/ssh_public_key/index.html), which was not goal of this project and the parser was inspired by an existing project.*

##### Metadata information
Section `meta` contains basic data about the parser, reference to documentation (`xref`), specification of supported file extension  `bin`, encoding, etc.

##### SSH version exchange ([RFC](https://tools.ietf.org/html/rfc4253#section-4.2))

Firstly, SSH identification must be exchanged after establishing a connection. It has the following format:<br>
```SSH-protoversion-softwareversion SP comments CR LF```

It must start with a string `SSH-` followed by a version `2.0`, software version like `OpenSSHv1`. Comments are optional and typically not used.

Corresponding type in Kaitai parser is `identification_string`. Since `comments` section is fully optional and the space `SP` is present only if the comment is as well, parser creates a substream up to `CR` and parses it accordingly. For possible compatibility with older version this parser does not enforce version `2.0`.

##### SSH packet ([RFC](https://tools.ietf.org/html/rfc4253#section-6))

After the exchange of SSH identification string, all messages have the following structure:
```
uint32    packet_length
byte      padding_length
byte[n1]  payload; n1 = packet_length - padding_length - 1
byte[n2]  random padding; n2 = padding_length
byte[m]   mac (Message Authentication Code - MAC); m = mac_length
```
A corresponding type in Kaitai parser is `ssh_packet`. 
