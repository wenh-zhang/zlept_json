#ifndef __ZLEPTJSON_H__
#define __ZLEPTJSON_H__

#include <stddef.h>

typedef enum {
  ZLEPT_NULL,
  ZLEPT_FALSE,
  ZLEPT_TRUE,
  ZLEPT_NUMBER,
  ZLEPT_STRING,
  ZLEPT_ARRAY,
  ZLEPT_OBJECT
} zlept_type;

typedef struct {
  union {
    struct 
    {
      char* s;
      size_t len;
    }s;
    double n;
  }u;
  zlept_type type;
} zlept_value;

enum {
  ZLEPT_PARSE_OK = 0,
  ZLEPT_PARSE_EXPECT_VALUE,
  ZLEPT_PARSE_INVALID_VALUE,
  ZLEPT_PARSE_ROOT_NOT_SINGULAR,
  ZLEPT_PARSE_NUMBER_TOO_BIG,
  ZLEPT_PARSE_MISS_QUOTATION_MARK,
  ZLEPT_PARSE_INVALID_STRING_ESCAPE,
  ZLEPT_PARSE_INVALID_STRING_CHAR,
  ZLEPT_PARSE_INVALID_UNICODE_HEX,
  ZLEPT_PARSE_INVALID_UNICODE_SURROGATE
};

int zlept_parse(zlept_value* v, const char* json);
zlept_type zlept_get_type(const zlept_value* v);

#define zlept_init(v)       \
  do {                     \
    (v)->type = ZLEPT_NULL; \
  } while (0)

void zlept_free(zlept_value* v);

#define zlept_set_null(v) zlept_free(v)

int zlept_get_boolean(const zlept_value* v);
void zlept_set_boolean(zlept_value* v, int b);

double zlept_get_number(const zlept_value* v);
void zlept_set_number(zlept_value* v, double n);

const char* zlept_get_string(const zlept_value* v);
size_t zlept_get_string_length(const zlept_value* v);
void zlept_set_string(zlept_value* v, const char* s, size_t len);

#endif
