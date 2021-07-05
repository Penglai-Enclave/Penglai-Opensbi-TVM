#ifndef _KEY_H
#define _KEY_H

#define KEY_SIZE_BYTES 32

int m_derive_key(int key_type, unsigned char *enclave_hash, int key_size, char *okey);

#endif

