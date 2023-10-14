#include "zleptjson.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef ZLEPT_PARSE_STACK_INIT_SIZE
#define ZLEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)         \
  do {                        \
    assert(*c->json == (ch)); \
    c->json++;                \
  } while (0)

#define PUTC(c, ch)                                     \
  do {                                                  \
    *(char*)zlept_context_push(c, sizeof(char)) = (ch); \
  } while (0);

typedef struct {
  const char* json;
  char* stack;
  size_t size, top;
} zlept_context;

static void* zlept_context_push(zlept_context* c, size_t size) {
  void* ret;
  assert(size > 0);
  if (c->top + size >= c->size) {
    if (c->size == 0) {
      c->size = ZLEPT_PARSE_STACK_INIT_SIZE;
    }
    while (c->top + size >= c->size) {
      c->size += c->size >> 1;
    }
    c->stack = (char*)realloc(c->stack, c->size);
  }
  ret = c->stack + c->top;
  c->top += size;
  return ret;
}

static void* zlept_context_pop(zlept_context* c, size_t size) {
  assert(c->top >= size);
  return c->stack + (c->top -= size);
}

#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')

static void zlept_parse_whitespace(zlept_context* c) {
  const char* p = c->json;
  while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r') {
    p++;
  }
  c->json = p;
}

static int lept_parse_literal(zlept_context* c, zlept_value* v,
                              zlept_type expect, const char* expected_json) {
  size_t i;
  EXPECT(c, *expected_json);
  for (i = 0; expected_json[i + 1]; i++) {
    if (c->json[i] != expected_json[i + 1]) {
      return ZLEPT_PARSE_INVALID_VALUE;
    }
  }
  c->json += i;
  v->type = expect;
  return ZLEPT_PARSE_OK;
}

static int zlept_parse_number(zlept_context* c, zlept_value* v) {
  const char* p = c->json;
  if (*p == '-') p++;
  if (*p == '0')
    p++;
  else {
    if (!ISDIGIT1TO9(*p)) return ZLEPT_PARSE_INVALID_VALUE;
    for (p++; ISDIGIT(*p); p++)
      ;
  }
  if (*p == '.') {
    p++;
    if (!ISDIGIT(*p)) return ZLEPT_PARSE_INVALID_VALUE;
    for (p++; ISDIGIT(*p); p++)
      ;
  }
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '+' || *p == '-') p++;
    if (!ISDIGIT(*p)) return ZLEPT_PARSE_INVALID_VALUE;
    for (p++; ISDIGIT(*p); p++)
      ;
  }
  errno = 0;
  v->u.n = strtod(c->json, NULL);
  if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) {
    return ZLEPT_PARSE_NUMBER_TOO_BIG;
  }
  c->json = p;
  v->type = ZLEPT_NUMBER;
  return ZLEPT_PARSE_OK;
}

static int zlept_parse_string(zlept_context* c, zlept_value* v) {
  size_t head = c->top, len;
  const char* p;
  EXPECT(c, '\"');
  p = c->json;
  for (;;) {
    char ch = *p++;
    switch (ch) {
      case '\\':
        switch (*p++) {
          case '\"':
            PUTC(c, '\"');
            break;
          case '\\':
            PUTC(c, '\\');
            break;
          case '/':
            PUTC(c, '/');
            break;
          case 'b':
            PUTC(c, '\b');
            break;
          case 'f':
            PUTC(c, '\f');
            break;
          case 'n':
            PUTC(c, '\n');
            break;
          case 'r':
            PUTC(c, '\r');
            break;
          case 't':
            PUTC(c, '\t');
            break;
          default:
            c->top = head;
            return ZLEPT_PARSE_INVALID_STRING_ESCAPE;
        };
        break;
      case '\"':
        len = c->top - head;
        zlept_set_string(v, zlept_context_pop(c, len), len);
        c->json = p;
        return ZLEPT_PARSE_OK;
      case '\0':
        c->top = head;
        return ZLEPT_PARSE_MISS_QUOTATION_MARK;
      default:
        if ((unsigned char)ch < 0x20) {
          c->top = head;
          return ZLEPT_PARSE_INVALID_STRING_CHAR;
        }
        PUTC(c, ch)
    }
  }
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
    case '\"':
      return zlept_parse_string(c, v);
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
  c.stack = NULL;
  c.size = c.top = 0;
  zlept_init(v);
  zlept_parse_whitespace(&c);
  if ((ret = zlept_parse_value(&c, v)) == ZLEPT_PARSE_OK) {
    zlept_parse_whitespace(&c);
    if (*c.json != '\0') {
      v->type = ZLEPT_NULL;
      ret = ZLEPT_PARSE_ROOT_NOT_SINGULAR;
    }
  }
  assert(c.top == 0);
  free(c.stack);
  return ret;
}

zlept_type zlept_get_type(const zlept_value* v) {
  assert(v != NULL);
  return v->type;
}

void zlept_free(zlept_value* v) {
  assert(v != NULL);
  if (v->type == ZLEPT_STRING) {
    free(v->u.s.s);
  }
  v->type = ZLEPT_NULL;
}

int zlept_get_boolean(const zlept_value* v) {
  assert(v != NULL && (v->type == ZLEPT_TRUE || v->type == ZLEPT_FALSE));
  return v->type == ZLEPT_TRUE;
}

void zlept_set_boolean(zlept_value* v, int b) {
  zlept_free(v);
  v->type = b ? ZLEPT_TRUE : ZLEPT_FALSE;
}

double zlept_get_number(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_NUMBER);
  return v->u.n;
}

void zlept_set_number(zlept_value* v, double n) {
  zlept_free(v);
  v->u.n = n;
  v->type = ZLEPT_NUMBER;
}

const char* zlept_get_string(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_STRING);
  return v->u.s.s;
}

size_t zlept_get_string_length(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_STRING);
  return v->u.s.len;
}

void zlept_set_string(zlept_value* v, const char* s, size_t len) {
  assert(s != NULL || len == 0);
  zlept_free(v);
  v->u.s.s = (char*)malloc(len + 1);
  memcpy(v->u.s.s, s, len);
  v->u.s.s[len] = '\0';
  v->u.s.len = len;
  v->type = ZLEPT_STRING;
}
