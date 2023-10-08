#include "zleptjson.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>

#define EXPECT(c, ch)         \
  do {                        \
    assert(*c->json == (ch)); \
    c->json++;                \
  } while (0)

typedef struct {
  const char* json;
} zlept_context;

#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')

static void zlept_parse_whitespace(zlept_context* c) {
  const char* p = c->json;
  while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r') {
    p++;
  }
  c->json = p;
}

static int lept_parse_literal(zlept_context* c, zlept_value* v, zlept_type expect, const char* expected_json) {
  size_t i;
  EXPECT(c, *expected_json);
  for(i = 0; expected_json[i + 1]; i++){
    if(c->json[i] != expected_json[i + 1]){
      return ZLEPT_PARSE_INVALID_VALUE;
    }
  }
  c->json += i;
  v->type = expect;
  return ZLEPT_PARSE_OK;
}

static int zlept_parse_number(zlept_context* c, zlept_value* v) {
  const char* p = c->json;
  /* \TODO validate number */
  if(*p == '-')p++;
  if(*p == '0')p++;
  else{
    if (!ISDIGIT1TO9(*p)) return ZLEPT_PARSE_INVALID_VALUE;
    for (p++; ISDIGIT(*p); p++);
  }
  if(*p == '.'){
    p++;
    if(!ISDIGIT(*p))return ZLEPT_PARSE_INVALID_VALUE;
    for(p++; ISDIGIT(*p); p++);
  }
  if(*p == 'e' || *p == 'E'){
    p++;
    if(*p == '+' || *p == '-') p++;
    if(!ISDIGIT(*p))return ZLEPT_PARSE_INVALID_VALUE;
    for (p++; ISDIGIT(*p); p++);
  }
  errno = 0;
  v->n = strtod(c->json, NULL);
  if(errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL)){
    return ZLEPT_PARSE_NUMBER_TOO_BIG;
  }
  c->json = p;
  v->type = ZLEPT_NUMBER;
  return ZLEPT_PARSE_OK;
}

static int zlept_parse_value(zlept_context* c, zlept_value* v) {
  switch (*c->json) {
    case 'n':
      return lept_parse_literal(c, v, ZLEPT_NULL, "null");
    case 't':
      return lept_parse_literal(c, v, ZLEPT_TRUE, "true");
    case 'f':
      return lept_parse_literal(c, v, ZLEPT_FALSE, "false");
    default:
      return zlept_parse_number(c, v);
    case '\0':
      return ZLEPT_PARSE_EXPECT_VALUE;
  }
}

int zlept_parse(zlept_value* v, const char* json) {
  zlept_context c;
  int ret;
  assert(v != NULL);
  v->type = ZLEPT_NULL;
  c.json = json;
  zlept_parse_whitespace(&c);
  if ((ret = zlept_parse_value(&c, v)) == ZLEPT_PARSE_OK) {
    zlept_parse_whitespace(&c);
    if (*c.json != '\0') {
      ret = ZLEPT_PARSE_ROOT_NOT_SINGULAR;
    }
  }
  return ret;
}

zlept_type zlept_get_type(const zlept_value* v) { return v->type; }

double zlept_get_number(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_NUMBER);
  return v->n;
}
