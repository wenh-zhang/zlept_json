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

typedef struct zlept_value zlept_value;
typedef struct zlept_member zlept_member ;

struct zlept_value {
  union {
    struct{
      zlept_member* m;
      size_t size;
    }o; /* object */
    struct {
      zlept_value* e;
      size_t size;
    } a; /* array */
    struct 
    {
      char* s;
      size_t len;
    }s;
    double n;
  }u;
  zlept_type type;
};

struct zlept_member{
  char* k;
  size_t klen;
  zlept_value v;
};

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
  ZLEPT_PARSE_INVALID_UNICODE_SURROGATE,
  ZLEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET,
  ZLEPT_PARSE_MISS_KEY,
  ZLEPT_PARSE_MISS_COLON,
  ZLEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET
};
/* 解析json字符串 */
int zlept_parse(zlept_value* v, const char* json);
/* 生成json字符串 */
char* zlept_stringify(const zlept_value* v, size_t* length);

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
size_t zlept_get_array_size(const zlept_value* v);
zlept_value* zlept_get_array_element(const zlept_value* v, size_t index);

size_t zlept_get_object_size(const zlept_value* v);
const char* zlept_get_object_key(const zlept_value* v, size_t index);
size_t zlept_get_object_key_length(const zlept_value* v, size_t index);
zlept_value* zlept_get_object_value(const zlept_value* v, size_t index);

#endif
