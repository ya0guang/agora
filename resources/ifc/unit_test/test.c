#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 64

sgx_private void *sgx_malloc(size_t size);
void sgx_free(sgx_private void *ptr);
void sgx_write(const char *filename, sgx_private int value);

struct key {
  sgx_private int *key;
  int sign;
};

sgx_private int test_struct_1(struct key *k, int i) {
  int x = k->key[i];
  return x;
}

int test_struct_2(struct key *k) { return k->sign; }

struct key *copy_key(struct key *k) {
  struct key *new_key = malloc(sizeof(struct key));
  if (!new_key) {
    return NULL;
  }
  new_key->key = sgx_malloc(KEY_SIZE * sizeof(sgx_private int));
  if (!new_key->key) {
    free(new_key);
    return NULL;
  }
  memcpy(new_key->key, k->key, KEY_SIZE * sizeof(int));
  new_key->sign = k->sign;
  return k;
}

int is_valid_key(struct key *k) {
  if (k == NULL || k->key == NULL) {
    return -1;
  }
  for (int i = 0; i < KEY_SIZE; i++) {
    if (k->key[i] < 0 || k->key[i] > 100) {
      return -1;
    }
  }
  return 0;
}

// use key to encrypt data
int enc_dec(struct key *k, sgx_private int *data, sgx_private int data_size) {
  if (is_valid_key(k) != 0) {
    return -1;
  }
  for (int i = 0; i < data_size; i++) {
    data[i] ^= k->key[i % KEY_SIZE];
  }
  return 0;
}

sgx_private int *generate_data(int size) {
  sgx_private int *data = sgx_malloc(size * sizeof(sgx_private int));
  if (!data) {
    return NULL;
  }
  for (int i = 0; i < size; i++) {
    data[i] = rand() % 256; // random data
  }
  return data;
}

sgx_private int process_data(sgx_private int *data, int size) {
  if (data == NULL || size <= 0) {
    return -1;
  }
  int sum = 0;
  for (int i = 0; i < size; i++) {
    sum += data[i];
  }
  return sum;
}

void matrix_multiply(sgx_private int *a, sgx_private int *b,
                     sgx_private int *result, int n) {
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < n; j++) {
      result[i * n + j] = 0;
      for (int k = 0; k < n; k++) {
        result[i * n + j] += a[i * n + k] * b[k * n + j];
      }
    }
  }
}

int main(int argc, char **argv) {
  struct key *k = malloc(sizeof(struct key));
  if (!k) {
    return -1;
  }
  k->key = sgx_malloc(KEY_SIZE * sizeof(sgx_private int));
  if (!k->key) {
    free(k);
    return -1;
  }
  for (int i = 0; i < KEY_SIZE; i++) {
    k->key[i] = rand() % 100; // random key
  }
  k->sign = 1;

  sgx_private int *data = generate_data(100);
  if (!data) {
    sgx_free(k->key);
    free(k);
    return -1;
  }

  if (enc_dec(k, data, 100) != 0) {
    sgx_free(data);
    sgx_free(k->key);
    free(k);
    return -1;
  }

  int sum = process_data(data, 100);
  // write the sum to a log file
  sgx_write("./current.log", sum);

  sgx_free(data);
  sgx_free(k->key);
  free(k);

  return 0;
}
