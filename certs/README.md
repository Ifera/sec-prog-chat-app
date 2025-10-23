# TLS Certificates Directory

This repo includes `dev_cert.pem` and `dev_key.pem`, self-signed TLS certificates for local development/demo.

They were generated on Windows using [mkcert](https://github.com/FiloSottile/mkcert). (Follow mkcert’s docs for setup on Windows/Unix.) 

Commands:

1. Install mkcert and the local CA (one-time):

```cmd
mkcert -install
```

2. Generate certificates for localhost:

```cmd
mkcert localhost 127.0.0.1 ::1
```

The resulting files were copied, renamed, and placed in this directory.


# Group 59
- Muhammad Tayyab Rashid - a1988298
- Nguyen Duc Tung Bui - a1976012
- Guilin Luo - a1989840
- Mazharul Islam Rakib - a1990942
- Masud Ahammad - a1993200