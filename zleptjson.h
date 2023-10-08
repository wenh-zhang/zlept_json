#ifndef __ZLEPTJSON_H__
#define __ZLEPTJSON_H__

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
  double n;
  zlept_type type;
} zlept_value;

enum {
  ZLEPT_PARSE_OK = 0,
  ZLEPT_PARSE_EXPECT_VALUE,
  ZLEPT_PARSE_INVALID_VALUE,
  ZLEPT_PARSE_ROOT_NOT_SINGULAR,
  ZLEPT_PARSE_NUMBER_TOO_BIG
};

int zlept_parse(zlept_value* v, const char* json);
zlept_type zlept_get_type(const zlept_value* v);
double zlept_get_number(const zlept_value* v);

#endif
